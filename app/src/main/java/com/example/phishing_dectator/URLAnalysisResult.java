package com.example.phishing_dectator; // Ensure this matches your package name

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class URLAnalysisResult {

    private final List<String> threats;
    private ThreatLevel threatLevel;

    // Constructor
    public URLAnalysisResult() {
        threats = new ArrayList<>();
        threatLevel = ThreatLevel.LOW; // Default to LOW risk
    }

    // Add a threat to the analysis result
    public void addThreat(String threatName, String description) {
        threats.add(threatName + ": " + description);
        updateThreatLevel();
    }

    // Get the list of identified threats
    public List<String> getThreats() {
        return threats;
    }

    // Get the current threat level
    public ThreatLevel getThreatLevel() {
        return threatLevel;
    }

    // Determine threat level based on number of threats
    private void updateThreatLevel() {
        if (threats.size() > 2) {
            threatLevel = ThreatLevel.HIGH;
        } else if (threats.size() > 0) {
            threatLevel = ThreatLevel.MEDIUM;
        }
    }

    // URL Analysis Function - Updated with Connection Checks and Threat Detection
    public static URLAnalysisResult analyzeUrl(String urlStr) {
        URLAnalysisResult result = new URLAnalysisResult();

        // Validate the URL
        if (urlStr == null || urlStr.isEmpty() || !android.util.Patterns.WEB_URL.matcher(urlStr).matches()) {
            result.addThreat("Invalid URL", "The entered URL is not valid.");
            return result;
        }

        try {
            URL url = new URL(urlStr);

            // Check if the URL uses HTTPS (Secure Connection)
            if (!url.getProtocol().equalsIgnoreCase("https")) {
                result.addThreat("Non-secure connection (HTTP)", "No HTTPS encryption.");
            }

            // Check for suspicious phishing keywords in the URL
            String[] phishingKeywords = {"login", "verify", "banking", "secure", "update"};
            for (String keyword : phishingKeywords) {
                if (urlStr.toLowerCase().contains(keyword)) {
                    result.addThreat("Suspicious Keyword", "The URL contains a potential phishing-related keyword: " + keyword);
                }
            }

        } catch (Exception e) {
            result.addThreat("Error", "Failed to analyze URL: " + e.getMessage());
        }

        return result;
    }

    // Enum to define threat levels
    public enum ThreatLevel {
        LOW("Low"), MEDIUM("Medium"), HIGH("High");

        private final String displayName;

        ThreatLevel(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }
}
