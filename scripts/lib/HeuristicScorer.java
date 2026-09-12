package lib;

import java.util.*;

/**
 * Calculates weighted threat risk scores (0-100) and classifies severity levels.
 * Rendering of the triage summary box belongs to the report writers.
 */
public class HeuristicScorer {

    public static class ThreatIndicator {
        public final String category;
        public final String description;
        public final String mitreId;
        public final int weight;

        public ThreatIndicator(String category, String description, String mitreId, int weight) {
            this.category = category;
            this.description = description;
            this.mitreId = mitreId;
            this.weight = weight;
        }
    }

    public static class ScoreResult {
        public final int score;
        public final String level;
        public final List<ThreatIndicator> indicators;

        public ScoreResult(int score, String level, List<ThreatIndicator> indicators) {
            this.score = score;
            this.level = level;
            this.indicators = indicators;
        }
    }

    public static ScoreResult computeScore(List<ThreatIndicator> indicators, boolean isSnes) {
        if (isSnes) {
            return new ScoreResult(0, "INFORMATIONAL", indicators);
        }

        int score = 0;
        Set<String> seen = new HashSet<>();
        for (ThreatIndicator ti : indicators) {
            String key = ti.category + "::" + ti.description;
            if (seen.add(key)) {
                score += ti.weight;
            }
        }

        int finalScore = Math.min(100, score);
        String level;
        if (finalScore >= 80) level = "CRITICAL";
        else if (finalScore >= 60) level = "HIGH";
        else if (finalScore >= 30) level = "MEDIUM";
        else level = "LOW";

        return new ScoreResult(finalScore, level, indicators);
    }
}
