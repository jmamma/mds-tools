#include "certify.hpp"

#include "emulator.hpp"
#include "layout.hpp"
#include "services.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <set>
#include <vector>

namespace mds {
namespace {

using dsp56k::MemArea_P;
using dsp56k::MemArea_X;
using dsp56k::MemArea_Y;

constexpr uint32_t kBlocks = 32, kLongBlocks = 1024, kRamBlocks = 65, kRetriggerBlock = 2;
constexpr uint32_t kQuickBlocks = kRetriggerBlock + 2;
constexpr size_t kLongVectors = 3;

using Settings = std::array<uint8_t, 8>;

class Canary {
public:
    explicit Canary(uint32_t seed) : state_(seed * 0x9e3779b9u | 1u) {}
    uint32_t operator()() {
        state_ ^= state_ << 13;
        state_ ^= state_ >> 17;
        state_ ^= state_ << 5;
        return state_ & kMask24;
    }
    uint64_t wide() { return static_cast<uint64_t>((*this)()) << 32 | static_cast<uint64_t>((*this)()) << 8; }

private:
    uint32_t state_;
};

bool discrete(const Parameter& parameter) {
    return parameter.conversion() == kBoolean || parameter.conversion() == kIndex;
}

std::vector<Settings> setting_vectors(const Package& package, CheckMode mode) {
    const auto& parameters = package.parameters;
    const size_t count = parameters.size();
    std::vector<Settings> vectors;
    std::set<Settings> seen;
    const auto add = [&](const Settings& settings) {
        if (seen.insert(settings).second) vectors.push_back(settings);
    };
    Settings defaults{}, minimum{}, maximum{};
    for (size_t index = 0; index != count; ++index) {
        defaults[index] = parameters[index].default_value;
        minimum[index] = parameters[index].minimum;
        maximum[index] = parameters[index].maximum;
    }
    add(defaults);
    add(minimum);
    add(maximum);
    if (mode == CheckMode::Quick) return vectors;
    for (size_t index = 0; index != count; ++index) {
        Settings settings = defaults;
        settings[index] = minimum[index];
        add(settings);
        settings[index] = maximum[index];
        add(settings);
        settings = maximum;
        settings[index] = minimum[index];
        add(settings);
        settings = minimum;
        settings[index] = maximum[index];
        add(settings);
    }
    for (size_t index = 0; index != count; ++index) {
        if (!discrete(parameters[index])) continue;
        for (unsigned value = minimum[index]; value <= maximum[index]; ++value) {
            Settings settings = maximum;
            settings[index] = static_cast<uint8_t>(value);
            add(settings);
            settings = defaults;
            settings[index] = static_cast<uint8_t>(value);
            add(settings);
        }
        for (size_t other = index + 1; other != count; ++other) {
            if (!discrete(parameters[other])) continue;
            const unsigned first = maximum[index] - minimum[index] + 1u;
            const unsigned second = maximum[other] - minimum[other] + 1u;
            if (first * second > 256) continue;
            for (unsigned a = minimum[index]; a <= maximum[index]; ++a)
                for (unsigned b = minimum[other]; b <= maximum[other]; ++b) {
                    Settings settings = maximum;
                    settings[index] = static_cast<uint8_t>(a);
                    settings[other] = static_cast<uint8_t>(b);
                    add(settings);
                }
        }
    }
    return vectors;
}

// The transition pass's settings: the defaults, the minimum and the maximum,
// and each parameter at its minimum and its maximum on top of each of those.
// The sweeps that follow find the values in between.
std::vector<Settings> transition_settings(const Package& package) {
    std::vector<Settings> settings;
    std::set<Settings> seen;
    const auto add = [&](const Settings& candidate) {
        if (seen.insert(candidate).second) settings.push_back(candidate);
    };
    Settings defaults{}, minimum{}, maximum{};
    for (size_t index = 0; index != package.parameters.size(); ++index) {
        defaults[index] = package.parameters[index].default_value;
        minimum[index] = package.parameters[index].minimum;
        maximum[index] = package.parameters[index].maximum;
    }
    for (const Settings& corner : {defaults, minimum, maximum}) add(corner);
    for (size_t index = 0; index != package.parameters.size(); ++index)
        for (const Settings& corner : {defaults, minimum, maximum})
            for (const uint8_t value : {minimum[index], maximum[index]}) {
                Settings candidate = corner;
                candidate[index] = value;
                add(candidate);
            }
    return settings;
}

// The chain's settings: each continuous parameter at every eighth of its
// range on top of the defaults, the minimum and the maximum.
std::vector<Settings> chain_settings(const Package& package) {
    std::vector<Settings> settings;
    std::set<Settings> seen;
    Settings defaults{}, minimum{}, maximum{};
    for (size_t index = 0; index != package.parameters.size(); ++index) {
        defaults[index] = package.parameters[index].default_value;
        minimum[index] = package.parameters[index].minimum;
        maximum[index] = package.parameters[index].maximum;
    }
    for (size_t index = 0; index != package.parameters.size(); ++index) {
        const Parameter& parameter = package.parameters[index];
        if (discrete(parameter)) continue;
        for (const Settings& corner : {defaults, minimum, maximum})
            for (unsigned eighth = 1; eighth != 8; ++eighth) {
                Settings candidate = corner;
                candidate[index] = static_cast<uint8_t>(parameter.minimum +
                                                        (parameter.maximum - parameter.minimum) * eighth / 8u);
                if (seen.insert(candidate).second) settings.push_back(candidate);
            }
    }
    return settings;
}

std::string describe_settings(const Package& package, const Settings& settings) {
    std::string text;
    for (size_t index = 0; index != package.parameters.size(); ++index)
        text += (index ? " " : "") + package.parameters[index].name + "=" + std::to_string(settings[index]);
    return text;
}

// A de Bruijn sequence of order 2 over `symbols` symbols: read cyclically,
// every ordered pair of symbols follows each other exactly once.
std::vector<size_t> de_bruijn_pairs(size_t symbols) {
    std::vector<size_t> sequence, a(3, 0);
    std::function<void(size_t, size_t)> step = [&](size_t t, size_t p) {
        if (t > 2) {
            if (2 % p == 0) sequence.insert(sequence.end(), a.begin() + 1, a.begin() + 1 + static_cast<long>(p));
            return;
        }
        a[t] = a[t - p];
        step(t + 1, p);
        for (size_t j = a[t - p] + 1; j < symbols; ++j) {
            a[t] = j;
            step(t + 1, t);
        }
    };
    step(1, 1);
    return sequence;
}

struct Run {
    bool ok = false;
    std::string error;
    std::array<uint64_t, kModels> track{}, machine{}, block{}, init{};
    // Peaks: the worst block of the transition pass and of the random tail,
    // kept apart from the standard vectors' figures above.
    std::array<uint64_t, kModels> transition{}, tail{};
    // What each peak block was, for whoever wants to take it out.
    std::array<std::string, kModels> transition_detail, tail_detail;
    uint64_t nominal = 0;
    size_t blocks = 0;
    std::vector<uint32_t> signature;
    std::vector<uint32_t> origin;
    std::vector<uint32_t> words;
};

uint32_t origin(size_t vector, uint32_t block, uint32_t track, uint32_t kind) {
    return static_cast<uint32_t>(vector) << 20 | std::min<uint32_t>(block, 0x3fff) << 6 | track << 2 | kind;
}

std::string describe(uint32_t origin, uint32_t word) {
    static const char* const kinds[] = {"its RENDER output", "its X state", "its Y state", "its track external memory"};
    return std::string(kinds[origin & 3]) + " (track " + std::to_string((origin >> 2 & 15) + 1) + ", block " +
           std::to_string(origin >> 6 & 0x3fff) + ", parameter setting " + std::to_string(origin >> 20) +
           ", word " + std::to_string(word) + ")";
}

class Qualification {
public:
    Qualification(const Package& package, uint32_t base, uint32_t seed, Hardware hardware = Hardware::Mk2UW)
        : package_(package), base_(base), seed_(seed), canary_(seed), services_(hardware) {}

    std::vector<std::string> scan_loops() {
        prepare();
        return emulator_.scan_loops();
    }

    Run run(const std::vector<Settings>& vectors, bool long_runs, CheckMode mode, bool with_tail = false) {
        prepare();
        const bool ram = package_.imports_symbol(kSymRamWorkspace) || package_.imports_symbol(kSymRamRecord);
        std::vector<uint32_t> tempos{120};
        if (std::any_of(package_.parameters.begin(), package_.parameters.end(),
                        [](const Parameter& p) { return p.conversion() == kTempo; }))
            tempos = {20, 120, 280};
        const unsigned trigger_kinds = package_.imports_symbol(kSymTriggerInfo) ? 2u : 1u;
        for (uint32_t tempo : tempos)
            for (unsigned repeat = 0; repeat != trigger_kinds; ++repeat)
                for (size_t vector = 0; vector != vectors.size(); ++vector) {
                    uint32_t blocks = kQuickBlocks;
                    if (mode == CheckMode::Full) {
                        blocks = ram ? kRamBlocks : kBlocks;
                        if (long_runs && vector < kLongVectors) blocks = kLongBlocks;
                        if (const char* count = std::getenv("MDS_CERTIFIER_BLOCKS"))
                            blocks = std::max<uint32_t>(blocks, static_cast<uint32_t>(std::atoi(count)));
                    }
                    tempo_ = tempo;
                    repeat_ = repeat != 0;
                    services_.reset(seed_ + static_cast<uint32_t>(vector), !ram);
                    assign(vectors[vector]);
                    vector_ = vector;
                    for (uint32_t block = 0; block != blocks; ++block)
                        if (!render_block(block)) return std::move(result_);
                    const auto keep = [this, vector](uint32_t value, uint32_t track, uint32_t kind, uint32_t word) {
                        result_.signature.push_back(value);
                        result_.origin.push_back(origin(vector, 0, track, kind));
                        result_.words.push_back(word);
                    };
                    for (uint32_t track = 0; track != kTracks; ++track) {
                        for (uint32_t word = 0; word != package_.x_words; ++word)
                            keep(emulator_.get(MemArea_X, workset(track) + word), track, 1, word);
                        for (uint32_t word = state_from(); word < package_.y_words; ++word)
                            keep(emulator_.get(MemArea_Y, workset(track) + word), track, 2, word);

                        if (package_.imports_symbol(kSymTrackMemory))
                            for (uint32_t word = 0; word != kTrackMemoryWords; ++word) {
                                const uint32_t value = emulator_.get(MemArea_X, track_memory(track) + word);
                                if (value == initial_track_memory_[track * kTrackMemoryWords + word]) continue;
                                keep(word, track, 3, word);
                                keep(value, track, 3, word);
                            }
                    }
                }
        // The transition pass runs at the first DRAM and the first SRAM
        // placement, where the long runs are.
        if (mode == CheckMode::Full && long_runs && !std::getenv("MDS_CERTIFIER_NO_TRANSITIONS") &&
            !transitions(transition_settings(package_)))
            return std::move(result_);
        if (mode == CheckMode::Full && with_tail && !std::getenv("MDS_CERTIFIER_NO_TAIL") && !random_tail())
            return std::move(result_);
        result_.ok = true;
        return std::move(result_);
    }

    // One track runs a single continuous schedule in which every ordered pair
    // of settings follows each other, three times over: with a trigger, with
    // no trigger, and with INIT and a trigger.  Nothing is reset between the
    // changes, so each finds the machine's oscillators, slides and lines
    // somewhere new; the blocks between changes cycle through kDwell, and
    // every block is measured.
    bool transitions(const std::vector<Settings>& settings) {
        static const uint32_t kDwell[] = {1, 2, 3, 5, 8, 13};
        constexpr uint32_t kTrack = 0;
        const std::vector<size_t> order = de_bruijn_pairs(settings.size());
        tempo_ = 120;
        repeat_ = false;
        vector_ = settings.size();
        assign(settings[order[0]]);
        transition_.fill(0);
        worst_ = {};
        uint32_t block = 0;
        size_t step = 0;
        if (!transition_block(kTrack, block++, true, true, 0)) return false;
        for (unsigned kind = 0; kind != 3; ++kind)
            for (size_t index = 1; index <= order.size(); ++index, ++step) {
                source_ = settings[order[index - 1]];
                target_ = settings[order[index % order.size()]];
                kind_ = kind;
                set_parameters(kTrack, target_);
                const uint32_t dwell = kDwell[step % (sizeof kDwell / sizeof kDwell[0])];
                for (uint32_t held = 0; held != dwell; ++held)
                    if (!transition_block(kTrack, block++, held == 0 && kind == 2, held == 0 && kind != 1,
                                          held == 0 ? 1u + kind : 0u))
                        return false;
            }
        // Then one chain through the wider settings, each reached once with
        // each kind of event and held longer, for the costs that depend on
        // where a setting lands rather than where it came from.
        const std::array<Worst, kModels> grid_worst = worst_;
        static const uint32_t kHold[] = {1, 2, 3, 5, 8, 13, 21, 34};
        const std::vector<Settings> chain = chain_settings(package_);
        for (unsigned kind = 0; kind != 3 && !chain.empty(); ++kind)
            for (size_t index = 0; index != chain.size(); ++index, ++step) {
                source_ = target_;
                target_ = chain[index];
                kind_ = kind;
                set_parameters(kTrack, target_);
                const uint32_t hold = kHold[step % (sizeof kHold / sizeof kHold[0])];
                for (uint32_t held = 0; held != hold; ++held)
                    if (!transition_block(kTrack, block++, held == 0 && kind == 2, held == 0 && kind != 1,
                                          held == 0 ? 1u + kind : 0u))
                        return false;
            }
        const uint32_t grid_blocks = block;
        const std::array<uint64_t, kModels> grid = transition_;
        // From the worst transition for each model, sweep one parameter at a
        // time, first the target's and then the source's: every fourth value,
        // then the values beside the best of those, keeping any value that
        // raises that model's cost, until a whole round raises nothing.
        // The climb starts twice, from the grid's worst transition and from
        // the worst after the chain, since a climb from one start can stop on
        // a lower peak than the other's.
        for (unsigned model : {static_cast<unsigned>(kMk2), static_cast<unsigned>(kMk1)})
          for (unsigned from = 0; from != 2; ++from) {
            const Worst start = from == 0 ? grid_worst[model] : worst_[model];
            if (from == 1 && start.source == grid_worst[model].source && start.target == grid_worst[model].target &&
                start.kind == grid_worst[model].kind)
                continue;
            Worst best = start;
            for (unsigned round = 0; round != 4; ++round) {
                bool raised = false;
                for (bool on_source : {false, true})
                    for (size_t parameter = 0; parameter != package_.parameters.size(); ++parameter) {
                        const Parameter& p = package_.parameters[parameter];
                        const auto value_of = [&](const Worst& w) {
                            return (on_source ? w.source : w.target)[parameter];
                        };
                        const auto try_value = [&](unsigned value) {
                            Worst candidate = best;
                            (on_source ? candidate.source : candidate.target)[parameter] = static_cast<uint8_t>(value);
                            uint64_t cost = 0;
                            if (!evaluate(kTrack, candidate, model, block, cost)) return false;
                            if (cost > best.cost) {
                                candidate.cost = cost;
                                best = candidate;
                                raised = true;
                            }
                            return true;
                        };
                        const unsigned stride = p.maximum - p.minimum >= 16 ? 4u : 1u;
                        for (unsigned value = p.minimum; value <= p.maximum; value += stride)
                            if (!try_value(value)) return false;
                        if (stride == 1) continue;
                        const unsigned centre = value_of(best);
                        for (unsigned value = centre > p.minimum + 3 ? centre - 3 : p.minimum;
                             value <= std::min<unsigned>(p.maximum, centre + 3); ++value)
                            if (value != centre && !try_value(value)) return false;
                    }
                if (!raised) break;
            }
            // Then when it lands: the same transition after 1 to 64 blocks of
            // the source, so the change meets its oscillators' phases and its
            // lines' write points at every block of a long cycle.
            for (uint32_t settle = 1; settle <= 64; ++settle) {
                Worst candidate = best;
                candidate.settle = settle;
                uint64_t cost = 0;
                if (!evaluate(kTrack, candidate, model, block, cost)) return false;
                if (cost > best.cost) {
                    candidate.cost = cost;
                    best = candidate;
                }
            }
        }
        if (std::getenv("MDS_CERTIFIER_TRACE_TRANSITIONS"))
            std::fprintf(stderr,
                         "transitions: %zu settings, %zu pairs, %u grid blocks, peak mk1 %llu mk2 %llu; "
                         "%u blocks after the sweeps, peak mk1 %llu mk2 %llu\n",
                         settings.size(), order.size(), grid_blocks, static_cast<unsigned long long>(grid[kMk1]),
                         static_cast<unsigned long long>(grid[kMk2]), block,
                         static_cast<unsigned long long>(transition_[kMk1]),
                         static_cast<unsigned long long>(transition_[kMk2]));
        return true;
    }

    // The random tail: all sixteen tracks for kTailBlocks blocks at each of a
    // few fixed seeds, every track with its own triggers, re-INITs and
    // changes of one to three parameters (towards their ends), and the
    // neighbour buffers carrying moving sawtooths.  Its outputs stay out of
    // the signature, since it runs in the first qualification only.
    bool random_tail() {
        constexpr uint32_t kTailBlocks = 3000;
        unsigned seeds = 9;
        if (const char* text = std::getenv("MDS_CERTIFIER_TAIL_SEEDS")) seeds = static_cast<unsigned>(std::atoi(text));
        const size_t count = package_.parameters.size();
        record_ = false;
        tempo_ = 120;
        repeat_ = false;
        for (unsigned seed = 1; seed <= seeds; ++seed) {
            Settings defaults{};
            for (size_t index = 0; index != count; ++index) defaults[index] = package_.parameters[index].default_value;
            assign(defaults);
            std::array<Settings, kTracks> now;
            now.fill(defaults);
            vector_ = 0;
            Canary rng(seed);
            for (uint32_t block = 0; block != kTailBlocks; ++block) {
                block_ = block;
                ++result_.blocks;
                emulator_.set(MemArea_X, kMainOutputCursor, kMainOutputRing + 64 * (block % 4));
                if (package_.neighbour)
                    for (uint32_t buffer = 0; buffer != 4; ++buffer) {
                        static const uint32_t inc[4] = {0x02f5c3u, 0x0451ebu, 0x0147aeu, 0x06b851u};
                        const uint32_t level = (block * (buffer + 3) + buffer * 40) % 320;
                        const int32_t env = level < 256 ? static_cast<int32_t>(level) : 0;
                        for (uint32_t word = 0; word != kBlock; ++word) {
                            const uint32_t phase = ((block * kBlock + word) * inc[buffer]) & kMask24;
                            const int32_t saw = static_cast<int32_t>(phase << 8) >> 8;
                            emulator_.set(MemArea_Y, kOutputBuffer[buffer] + word,
                                          static_cast<uint32_t>((saw / 256) * env) & kMask24);
                        }
                    }
                for (uint32_t track = 0; track != kTracks; ++track) {
                    emulator_.begin_track();
                    Costs costs;
                    const bool init = block == 0 || rng() % 300 == 0;
                    const bool trig = init || rng() % 9 == 0 || (block == 1 && track % 2 == 0);
                    const unsigned changes = rng() % 5 == 0 ? 1 + rng() % 3 : 0;
                    for (unsigned change = 0; change != changes && count != 0; ++change) {
                        const size_t index = rng() % count;
                        const Parameter& parameter = package_.parameters[index];
                        const unsigned span = parameter.maximum - parameter.minimum + 1u;
                        const unsigned pick = rng() % 4;
                        const uint8_t value = static_cast<uint8_t>(
                            pick == 0 ? parameter.minimum : pick == 1 ? parameter.maximum
                                                          : parameter.minimum + rng() % span);
                        emulator_.set(MemArea_Y, workset(track) + 1 + static_cast<uint32_t>(index),
                                      parameter_value(parameter, value, tempo_));
                        now[track][index] = value;
                    }
                    if (init && !routine(Routine::Init, track, costs)) return false;
                    if (trig && !routine(Routine::Trig, track, costs)) return false;
                    if (!routine(Routine::Render, track, costs)) return false;
                    for (unsigned model = 0; model != kModels; ++model)
                        if (costs.cycles[model] > result_.tail[model]) {
                            result_.tail[model] = costs.cycles[model];
                            result_.tail_detail[model] =
                                "random tail seed " + std::to_string(seed) + ", block " + std::to_string(block) +
                                ", track " + std::to_string(track + 1) + ":" + (init ? " INIT" : "") +
                                (trig ? " trigger" : "") + (changes ? " " + std::to_string(changes) + " change(s)" : "") +
                                (init || trig || changes ? "" : " no event") + "; " +
                                describe_settings(package_, now[track]);
                        }
                    result_.nominal = std::max(result_.nominal, costs.nominal);
                }
            }
        }
        record_ = true;
        return true;
    }

    struct Worst {
        Settings source{}, target{};
        unsigned kind = 0;
        uint32_t settle = 3;
        uint64_t cost = 0;
    };

    void set_parameters(uint32_t track, const Settings& settings) {
        for (size_t parameter = 0; parameter != package_.parameters.size(); ++parameter)
            emulator_.set(MemArea_Y, workset(track) + 1 + static_cast<uint32_t>(parameter),
                          parameter_value(package_.parameters[parameter], settings[parameter], tempo_));
    }

    // One transition on its own: the source with a trigger and `settle`
    // blocks in all, then the target with the transition's event and 13
    // blocks measured; `cost` is the worst of those for `model`.
    bool evaluate(uint32_t track, const Worst& transition, unsigned model, uint32_t& block, uint64_t& cost) {
        source_ = transition.source;
        target_ = transition.target;
        kind_ = transition.kind;
        set_parameters(track, transition.source);
        for (uint32_t held = 0; held != transition.settle; ++held)
            if (!transition_block(track, block++, false, held == 0, 0)) return false;
        set_parameters(track, transition.target);
        cost = 0;
        for (uint32_t held = 0; held != 13; ++held) {
            if (!transition_block(track, block++, held == 0 && transition.kind == 2,
                                  held == 0 && transition.kind != 1, held == 0 ? 1u + transition.kind : 0u))
                return false;
            cost = std::max(cost, last_[model]);
        }
        return true;
    }

    bool transition_block(uint32_t track, uint32_t block, bool init, bool trig, unsigned event) {
        if (!result_.error.empty()) return false;
        block_ = block;
        ++result_.blocks;
        if (package_.neighbour)
            for (uint32_t buffer = 0; buffer != 4; ++buffer)
                for (uint32_t word = 0; word != kBlock; ++word)
                    emulator_.set(MemArea_Y, kOutputBuffer[buffer] + word,
                                  (0x123456u * (buffer + 1) + word * (0x31001u + buffer * 0x0b0b0bu)) & kMask24);
        emulator_.set(MemArea_X, kMainOutputCursor, kMainOutputRing + 64 * (block % 4));
        emulator_.begin_track();
        Costs costs;
        if (init) {
            if (!routine(Routine::Init, track, costs)) return false;
            for (unsigned model = 0; model != kModels; ++model)
                result_.init[model] = std::max(result_.init[model], costs.cycles[model]);
        }
        if (trig && !routine(Routine::Trig, track, costs)) return false;
        if (!routine(Routine::Render, track, costs)) return false;
        since_ = event != 0 ? 0 : since_ + 1;
        for (unsigned model = 0; model != kModels; ++model) {
            if (costs.cycles[model] > result_.transition[model]) {
                static const char* const kinds[] = {"with a trigger", "with no trigger", "with INIT and a trigger"};
                result_.transition_detail[model] =
                    "transition pass, " + std::string(kinds[kind_]) + ", " +
                    (since_ == 0 ? std::string("in its block") : std::to_string(since_) + " block(s) after it") +
                    "; from " + describe_settings(package_, source_) + " to " + describe_settings(package_, target_);
            }
            result_.transition[model] = std::max(result_.transition[model], costs.cycles[model]);
            transition_[model] = std::max(transition_[model], costs.cycles[model]);
            last_[model] = costs.cycles[model];
            if (costs.cycles[model] > worst_[model].cost) worst_[model] = {source_, target_, kind_, 3u, costs.cycles[model]};
        }
        result_.nominal = std::max(result_.nominal, costs.nominal);
        if (std::getenv("MDS_CERTIFIER_TRACE_BLOCKS"))
            std::fprintf(stderr, "transition block %u event %u nominal %llu mk1 %llu mk2 %llu\n", block, event,
                         static_cast<unsigned long long>(costs.nominal),
                         static_cast<unsigned long long>(costs.cycles[kMk1]),
                         static_cast<unsigned long long>(costs.cycles[kMk2]));
        return true;
    }

private:
    uint32_t state_from() const {
        return package_.stereo_pair ? 10u : 1u + static_cast<uint32_t>(package_.parameters.size());
    }

    void prepare() {
        for (uint32_t index = 0; index != kSineWords; ++index) {
            const double value = std::sin(2.0 * M_PI * index / kSineWords) * 8388607.0;
            emulator_.set(MemArea_X, kSineTable + index, static_cast<uint32_t>(std::lround(value)) & kMask24);
        }
        for (uint32_t index = 0; index != kRingWords; ++index) {
            emulator_.set(MemArea_X, kInputRing + index, (index * 0x010203u + 0x0a0b0cu) & kMask24);
            emulator_.set(MemArea_X, kMainOutputRing + index, (index * 0x030507u ^ 0x05a5a5u) & kMask24);
        }
        emulator_.set(MemArea_X, kInputCursor, kInputRing);
        for (uint32_t descriptor = 0; descriptor != 4; ++descriptor)
            for (uint32_t back = 0; back != 4; ++back)
                emulator_.set(MemArea_Y, kDescriptors + descriptor * 4 + back, kOutputBuffer[(descriptor + 4 - back) % 4]);

        initial_track_memory_.resize(kTracks * kTrackMemoryWords);
        for (uint32_t word = 0; word != kTracks * kTrackMemoryWords; ++word) {
            initial_track_memory_[word] = canary_();
            emulator_.set(MemArea_X, kTrackMemory + word, initial_track_memory_[word]);
        }
        if (package_.imports_symbol(kSymRamWorkspace))
            for (uint32_t word = 0; word != kRamSlots * kRamSlotWords; ++word)
                emulator_.set(MemArea_X, kSampleMemory + word, canary_());
        emulator_.install(package_, base_, services_);
    }

    void assign(const Settings& settings) {
        for (uint32_t track = 0; track != kTracks; ++track) {
            const uint32_t base = workset(track);
            for (uint32_t word = 0; word != kWorksetWords; ++word) {
                emulator_.set(MemArea_X, base + word, word < package_.x_words ? 0 : canary_());
                emulator_.set(MemArea_Y, base + word, word < package_.y_words ? 0 : canary_());
            }
            for (size_t index = 0; index != package_.parameters.size(); ++index)
                emulator_.set(MemArea_Y, base + 1 + static_cast<uint32_t>(index),
                              parameter_value(package_.parameters[index], settings[index], tempo_));
            if (package_.stereo_pair) emulator_.set(MemArea_Y, base + 9, track % 2 == 0 ? 1u : 2u);
        }
    }

    bool render_block(uint32_t block) {
        if (!result_.error.empty()) return false;
        block_ = block;
        ++result_.blocks;

        if (package_.neighbour)
            for (uint32_t buffer = 0; buffer != 4; ++buffer)
                for (uint32_t word = 0; word != kBlock; ++word)
                    emulator_.set(MemArea_Y, kOutputBuffer[buffer] + word,
                                  (0x123456u * (buffer + 1) + word * (0x31001u + buffer * 0x0b0b0bu)) & kMask24);
        emulator_.set(MemArea_X, kMainOutputCursor, kMainOutputRing + 64 * (block % 4));
        std::array<uint64_t, kModels> total{};
        for (uint32_t track = 0; track != kTracks; ++track) {
            emulator_.begin_track();
            Costs costs;
            if (block == 0) {
                if (!routine(Routine::Init, track, costs)) return false;
                for (unsigned model = 0; model != kModels; ++model)
                    result_.init[model] = std::max(result_.init[model], costs.cycles[model]);
            }
            if ((block == 0 || block == kRetriggerBlock) && !routine(Routine::Trig, track, costs)) return false;
            if (!routine(Routine::Render, track, costs)) return false;
            for (unsigned model = 0; model != kModels; ++model) {
                const uint64_t clocks = costs.cycles[model];
                result_.machine[model] = std::max(result_.machine[model], costs.cycles[model]);
                result_.track[model] = std::max(result_.track[model], clocks);
                total[model] += clocks;
            }
            result_.nominal = std::max(result_.nominal, costs.nominal);
            if (std::getenv("MDS_CERTIFIER_TRACE_BLOCKS"))
                std::fprintf(stderr, "vector %zu block %u track %u nominal %llu mk1 %llu mk2 %llu\n", vector_, block,
                             track + 1, static_cast<unsigned long long>(costs.nominal),
                             static_cast<unsigned long long>(costs.cycles[kMk1]),
                             static_cast<unsigned long long>(costs.cycles[kMk2]));
        }
        for (unsigned model = 0; model != kModels; ++model)
            result_.block[model] = std::max(result_.block[model], total[model]);
        return true;
    }

    bool routine(Routine routine, uint32_t track, Costs& costs) {
        using namespace dsp56k;
        Permissions permissions;
        permissions.track = track;
        permissions.routine = routine;
        permissions.x_words = package_.x_words;
        permissions.y_words = package_.y_words;
        permissions.state_from = state_from();
        const bool samples = package_.imports_symbol(kSymSampleRead) || package_.imports_symbol(kSymRamRecord);
        permissions.temp_x = samples || package_.imports_symbol(kSymTempX);
        permissions.temp_y = samples || package_.imports_symbol(kSymTempY);
        permissions.track_memory = package_.imports_symbol(kSymTrackMemory);
        permissions.trigger_info = package_.imports_symbol(kSymTriggerInfo);
        if (routine == Routine::Trig)
            emulator_.set(MemArea_X, kTriggerInfo, repeat_ && block_ == kRetriggerBlock ? 1u << 16 : 0u);
        for (EReg reg : {Reg_R0, Reg_R1, Reg_R2, Reg_R3, Reg_R4, Reg_R5, Reg_R7, Reg_N0, Reg_N1, Reg_N2, Reg_N3,
                         Reg_N4, Reg_N5, Reg_N6, Reg_N7, Reg_X0, Reg_X1, Reg_Y0, Reg_Y1})
            emulator_.set_reg(reg, canary_());
        emulator_.set_accumulator(Reg_A, canary_.wide());
        emulator_.set_accumulator(Reg_B, canary_.wide());
        for (EReg reg : {Reg_M0, Reg_M1, Reg_M2, Reg_M3, Reg_M4, Reg_M5, Reg_M6, Reg_M7}) emulator_.set_reg(reg, kMask24);
        emulator_.set_reg(Reg_R6, workset(track));
        for (uint32_t word = 0; word != kBlock; ++word) {
            emulator_.set(MemArea_X, kTemp + word, canary_());
            emulator_.set(MemArea_Y, kTemp + word, canary_());
        }
        uint32_t entry = package_.trig;
        if (routine == Routine::Init) {
            entry = package_.init;
            emulator_.set_reg(Reg_R1, track);
        } else if (routine == Routine::Render) {
            entry = package_.render;
            permissions.output = kOutputBuffer[track % 4];
            emulator_.set(MemArea_Y, kDescriptorWord, kDescriptors + 4 * (track % 4));
            if (!package_.neighbour)
                for (uint32_t word = 0; word != kBlock; ++word)
                    emulator_.set(MemArea_Y, permissions.output + word, canary_());
            emulator_.set_reg(Reg_R7, permissions.output);
            emulator_.set_reg(Reg_M7, kBlock - 1);

            static const uint32_t m6[] = {kMask24, 0x0003ff, 0x00003f, 0x007fff};
            emulator_.set_reg(Reg_M6, m6[canary_() % 4]);
        }
        std::string error;
        if (!emulator_.call(base_ + entry, permissions, costs, error)) {
            static const char* const names[] = {"INIT", "TRIG", "RENDER"};
            result_.error = std::string(names[static_cast<int>(routine)]) + " on track " +
                            std::to_string(track + 1) + " (block " + std::to_string(block_) + ", parameter setting " +
                            std::to_string(vector_) + "): " + error;
            return false;
        }
        if (routine == Routine::Render) {
            if (permissions.output_written != 0xffffffffu) {
                result_.error = "RENDER on track " + std::to_string(track + 1) + " did not write all 32 output words";
                return false;
            }
            for (uint32_t word = 0; word != kBlock && record_; ++word) {
                result_.signature.push_back(emulator_.get(MemArea_Y, permissions.output + word));
                result_.origin.push_back(origin(vector_, block_, track, 0));
                result_.words.push_back(word);
            }
        }
        return true;
    }

    const Package& package_;
    uint32_t base_, seed_;
    Canary canary_;
    Emulator emulator_;
    Services services_;
    Run result_;
    std::array<uint64_t, kModels> transition_{}, last_{};
    bool record_ = true;
    uint32_t since_ = 0;
    Settings source_{}, target_{};
    unsigned kind_ = 0;
    std::array<Worst, kModels> worst_{};
    size_t vector_ = 0;
    uint32_t block_ = 0, tempo_ = 120;
    bool repeat_ = false;
    std::vector<uint32_t> initial_track_memory_;
};

}

std::vector<std::string> scan_loops(const Package& package) {
    return Qualification(package, kProgramRegion, 1).scan_loops();
}

Report certify(const Package& package, const std::function<void(const std::string&)>& progress, CheckMode mode) {
    Report report;
    report.development_only = mode == CheckMode::Quick;
    report.warnings = Qualification(package, kProgramRegion, 1).scan_loops();
    const auto vectors = setting_vectors(package, mode);
    report.vectors = vectors.size();

    int count = 1;
    if (mode == CheckMode::Full) {
        count = 8;
        if (const char* text = std::getenv("MDS_CERTIFIER_PLACEMENTS")) count = std::max(1, std::atoi(text));
    }
    struct Placement {
        uint32_t base;
        bool sram, long_runs;
    };
    std::vector<Placement> placements;
    for (bool sram : {false, true})
        for (int index = 0; index < count; ++index)
            placements.push_back({(sram ? kSramProgramRegion : kProgramRegion) + 0x400u * static_cast<uint32_t>(index) +
                                      (sram ? 128u : 512u) * static_cast<uint32_t>(index) / static_cast<uint32_t>(count),
                                  sram, index == 0});
    const bool sample_services = std::any_of(package.imports.begin(), package.imports.end(),
                                             [](const Import& item) { return item.kind == 5; });
    const std::vector<Hardware> hardware_profiles = sample_services
        ? std::vector<Hardware>{Hardware::NonUW, Hardware::Mk1UW, Hardware::Mk2UW}
        : std::vector<Hardware>{Hardware::Mk2UW};
    for (const Placement& placement : placements) {
        const uint32_t base = placement.base;
        if (progress) progress("placement " + std::to_string(report.placements + 1) + " of " +
                               std::to_string(placements.size()) + (placement.sram ? " (MKI SRAM)" : ""));
        const bool long_runs = placement.long_runs;
        for (Hardware hardware : hardware_profiles) {
            const std::string profile = !sample_services ? "" : hardware == Hardware::NonUW ? "non-UW: " :
                                        hardware == Hardware::Mk1UW ? "MKI UW: " : "MKII UW: ";
            Run first = Qualification(package, base, 0x1234u, hardware)
                            .run(vectors, long_runs, mode, long_runs && !placement.sram);
            if (!first.ok) {
                report.error = profile + first.error;
                return report;
            }
            Run second = Qualification(package, base, 0x5678u, hardware).run(vectors, long_runs, mode);
            if (!second.ok) {
                report.error = profile + second.error;
                return report;
            }
            if (first.signature != second.signature || first.track != second.track || first.block != second.block ||
                first.transition != second.transition) {
                report.error =
                    "output, state or cost depends on memory or registers the machine did not set "
                    "(uninitialized reads, or registers the standard leaves unspecified)";
                const size_t size = std::min(first.signature.size(), second.signature.size());
                for (size_t index = 0; index != size; ++index)
                    if (first.signature[index] != second.signature[index]) {
                        report.error += ": first in " + describe(first.origin[index], first.words[index]);
                        break;
                    }
                return report;
            }
            for (unsigned model = 0; model != kModels; ++model) {
                if (sample_services && ((hardware == Hardware::Mk1UW && model != kMk1) ||
                                        (hardware == Hardware::Mk2UW && model != kMk2))) continue;
                const uint64_t peak = std::max(first.transition[model], first.tail[model]);
                report.standard[model] = std::max(report.standard[model], first.machine[model]);
                if (peak > report.peak[model])
                    report.peak_detail[model] = (first.tail[model] > first.transition[model] ? first.tail_detail[model]
                                                                                            : first.transition_detail[model]) +
                                                " (placement " + std::to_string(report.placements + 1) + ")";
                report.peak[model] = std::max(report.peak[model], peak);
                report.track[model] = std::max({report.track[model], first.track[model], peak});
                report.machine[model] = std::max({report.machine[model], first.machine[model], peak});
                report.block[model] = std::max(report.block[model], first.block[model]);
                report.init[model] = std::max(report.init[model], first.init[model]);
            }
            if (placement.sram && (!sample_services || hardware != Hardware::Mk2UW)) {
                const uint64_t peak = std::max(first.transition[kMk1], first.tail[kMk1]);
                report.sram_standard = std::max(report.sram_standard, first.machine[kMk1]);
                if (peak > report.sram_peak)
                    report.sram_peak_detail = (first.tail[kMk1] > first.transition[kMk1] ? first.tail_detail[kMk1]
                                                                                         : first.transition_detail[kMk1]) +
                                              " (placement " + std::to_string(report.placements + 1) + ")";
                report.sram_peak = std::max(report.sram_peak, peak);
                report.sram_track = std::max({report.sram_track, first.track[kMk1], peak});
                report.sram_machine = std::max({report.sram_machine, first.machine[kMk1], peak});
                report.sram_block = std::max(report.sram_block, first.block[kMk1]);
                report.sram_init = std::max(report.sram_init, first.init[kMk1]);
            }
            report.nominal = std::max(report.nominal, first.nominal);
            report.blocks += first.blocks;
        }
        ++report.placements;
    }
    report.certified = mode == CheckMode::Full;
    report.development_checks_passed = mode == CheckMode::Quick;
    return report;
}

}
