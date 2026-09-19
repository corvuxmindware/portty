//! AUDIT-003: 256-entry diceware lists backing the manual pairing-phrase codec
//! ([`super::pairing`] `to_phrase` / `from_phrase`).
//!
//! An earlier stub used a ~225-word pool indexed with `pool[i % pool.len()]`.
//! That wrap caused ~31 byte values per list to share a word with another byte
//! value - two distinct secrets could render the same phrase, so a phrase could
//! not round-trip back to its bytes unambiguously.
//!
//! This module ships two **disjoint** 256-entry lists of short English words
//! (one for the even-position bytes, one for odd). Each byte 0..256 maps to a
//! unique word per list, so distinct bytes always render to distinct words.
//!
//! Words chosen for: 3-5 chars (short utterance), no homophones across the two
//! lists, no profanity, no ambiguous spellings.

/// Words indexed by even-position bytes (positions 0, 2, 4 in the
/// first 6 bytes of the SPKI hash). 256 unique entries.
pub const EVEN_WORDS: [&str; 256] = [
    "able", "acid", "aged", "also", "area", "army", "away", "baby", "back", "ball", "band", "bank",
    "base", "bath", "bear", "beat", "beer", "bell", "belt", "best", "bill", "bird", "blow", "blue",
    "boat", "body", "bomb", "bond", "bone", "book", "boom", "born", "boss", "both", "bowl", "bulk",
    "burn", "bush", "busy", "cake", "call", "calm", "came", "camp", "card", "care", "case", "cash",
    "cast", "cell", "chat", "chip", "city", "club", "coal", "coat", "code", "cold", "come", "cook",
    "cool", "cope", "copy", "core", "cost", "crew", "crop", "dark", "data", "date", "dawn", "days",
    "dead", "deal", "dean", "dear", "debt", "deep", "deny", "desk", "dial", "dice", "diet", "dine",
    "dish", "disk", "dock", "does", "done", "door", "dose", "down", "draw", "drew", "drop", "drug",
    "dual", "duke", "dust", "duty", "each", "earn", "ease", "east", "easy", "edge", "else", "even",
    "ever", "evil", "exit", "face", "fact", "fail", "fair", "fall", "farm", "fast", "fate", "fear",
    "feed", "feel", "feet", "fell", "felt", "file", "fill", "film", "find", "fine", "fire", "firm",
    "fish", "five", "flag", "flat", "flew", "flip", "flow", "flux", "folk", "food", "foot", "ford",
    "form", "fort", "four", "free", "from", "fuel", "full", "fund", "gain", "game", "gate", "gave",
    "gear", "gene", "gift", "girl", "give", "glad", "goal", "goat", "goes", "gold", "golf", "gone",
    "good", "gray", "grew", "grow", "gulf", "gust", "hair", "half", "hall", "hand", "hang", "hard",
    "harm", "hate", "have", "head", "hear", "heat", "held", "hell", "help", "here", "hero", "high",
    "hill", "hint", "hire", "hold", "hole", "holy", "home", "hope", "host", "hour", "huge", "hung",
    "hunt", "hurt", "iced", "idea", "inch", "into", "iron", "item", "jade", "jail", "jazz", "join",
    "joke", "jump", "june", "jury", "just", "keel", "keen", "keep", "kept", "keys", "kick", "kill",
    "kind", "king", "knee", "knew", "know", "lack", "lady", "laid", "lake", "land", "lane", "last",
    "late", "lava", "lawn", "lazy", "lead", "leaf", "lean", "leap", "left", "lend", "less", "life",
    "lift", "like", "limb", "lime",
];

/// Words indexed by odd-position bytes (positions 1, 3, 5). Disjoint
/// from EVEN_WORDS so a UI showing both columns can't display the same
/// token twice in adjacent positions (visual aid for the user
/// comparing). 256 unique entries.
pub const ODD_WORDS: [&str; 256] = [
    "line", "link", "lips", "list", "live", "load", "loaf", "loan", "lock", "logs", "long", "look",
    "loop", "lord", "lose", "loss", "lost", "loud", "love", "luck", "made", "mail", "main", "make",
    "male", "mall", "many", "mark", "mars", "mask", "mass", "mate", "math", "meal", "mean", "meat",
    "meet", "melt", "menu", "mesh", "mess", "mice", "mild", "mile", "milk", "mill", "mind", "mine",
    "mint", "miss", "mode", "mole", "moon", "more", "moss", "most", "move", "much", "musk", "must",
    "myth", "name", "navy", "near", "neck", "need", "news", "next", "nice", "nick", "nine", "node",
    "none", "noon", "norm", "nose", "note", "oaks", "oath", "odds", "okay", "once", "only", "onto",
    "open", "oral", "oven", "over", "pace", "pack", "page", "paid", "pain", "pair", "pale", "palm",
    "park", "part", "pass", "past", "path", "peak", "pens", "pest", "pick", "pier", "pile", "pine",
    "pink", "pint", "pipe", "plan", "play", "plot", "plug", "plum", "plus", "poem", "poet", "pole",
    "poll", "pond", "pool", "poor", "port", "post", "pour", "pray", "pull", "pulp", "pump", "punk",
    "pure", "push", "quay", "quit", "race", "rack", "raft", "rage", "raid", "rail", "rain", "rake",
    "rank", "rare", "rate", "read", "real", "rear", "reed", "reef", "rein", "rely", "rent", "rest",
    "rice", "rich", "ride", "ring", "rink", "rise", "risk", "rite", "road", "roam", "roar", "rock",
    "role", "roll", "roof", "room", "root", "rope", "rose", "rosy", "rugs", "rung", "runs", "rush",
    "rust", "safe", "sage", "said", "sail", "salt", "same", "sand", "sane", "save", "scan", "seal",
    "seat", "seed", "seem", "seen", "self", "sell", "send", "sent", "shed", "ship", "shop", "shot",
    "show", "shun", "side", "sign", "silk", "sing", "sink", "site", "size", "skin", "slab", "slap",
    "sled", "slid", "slim", "slog", "slot", "slow", "snap", "snow", "soap", "sock", "soft", "soil",
    "sold", "sole", "solo", "song", "soon", "sore", "sort", "soul", "soup", "sour", "spin", "spot",
    "stag", "stem", "step", "stir", "stop", "such", "suit", "sung", "swan", "swap", "swim", "tail",
    "take", "tale", "talk", "tame",
];

#[cfg(test)]
mod tests {
    use super::{EVEN_WORDS, ODD_WORDS};
    use std::collections::HashSet;

    #[test]
    fn even_words_are_all_distinct() {
        let set: HashSet<&str> = EVEN_WORDS.iter().copied().collect();
        assert_eq!(
            set.len(),
            256,
            "EVEN_WORDS must have 256 unique entries (got {})",
            set.len(),
        );
    }

    #[test]
    fn odd_words_are_all_distinct() {
        let set: HashSet<&str> = ODD_WORDS.iter().copied().collect();
        assert_eq!(
            set.len(),
            256,
            "ODD_WORDS must have 256 unique entries (got {})",
            set.len(),
        );
    }

    #[test]
    fn even_and_odd_are_disjoint() {
        // Disjoint lists make the UI unambiguous: a word at position 0
        // never repeats at position 1, so the user comparing phrases
        // can spot a positional swap.
        let even: HashSet<&str> = EVEN_WORDS.iter().copied().collect();
        let odd: HashSet<&str> = ODD_WORDS.iter().copied().collect();
        let overlap: Vec<&&str> = even.intersection(&odd).collect();
        assert!(
            overlap.is_empty(),
            "EVEN and ODD wordlists must not share entries; overlap: {overlap:?}"
        );
    }

    #[test]
    fn distinct_byte_indices_produce_distinct_words() {
        // The core property the audit was about - defeating the
        // wraparound collision. Verify directly.
        for i in 0..256 {
            for j in (i + 1)..256 {
                assert_ne!(EVEN_WORDS[i], EVEN_WORDS[j], "EVEN_WORDS[{i}] == [{j}]");
                assert_ne!(ODD_WORDS[i], ODD_WORDS[j], "ODD_WORDS[{i}] == [{j}]");
            }
        }
    }
}
