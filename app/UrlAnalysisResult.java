package com.example.phishing_dectator; // Adjust this package name to your actual package

import java.util.ArrayList;
import java.util.List;

public class UrlAnalysisResult {

    private List<String> threats;
    private ThreatLevel threatLevel;

    // Constructor
    public UrlAnalysisResult() {
        threats = new ArrayList<>();
        threatLevel = ThreatLevel.LOW; // Default to low threat level
    }

    // Method to add a new threat
    public void addThreat(String threatName, String description) {
        threats.add(threatName + ": " + description);
        updateThreatLevel();
    }

    // Get the list of threats
    public List<String> getThreats() {
        return threats;
    }

    // Get the threat level
    public ThreatLevel getThreatLevel() {
        return threatLevel;
    }

    // Update the threat level based on the number of threats
    private void updateThreatLevel() {
        if (threats.size() > 2) {
            threatLevel = ThreatLevel.HIGH; // High threat if there are more than 2 threats
        } else if (threats.size() > 0) {
            threatLevel = ThreatLevel.MEDIUM; // Medium threat if there are some threats
        }
    }

    // Enum to represent threat levels (LOW, MEDIUM, HIGH)
    public enum ThreatLevel {
        LOW("Low"),
        MEDIUM("Medium"),
        HIGH("High");

        private final String displayName;

        ThreatLevel(String displayName) {
            this.displayName = displayName;
        }

        // Get the display name of the threat level
        public String getDisplayName() {
            return displayName;
        }
    }
}
