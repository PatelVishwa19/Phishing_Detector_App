package com.example.phishing_dectator;

import android.annotation.SuppressLint;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.widget.*;
import androidx.appcompat.app.AppCompatActivity;
import androidx.cardview.widget.CardView;
import com.google.android.material.textfield.TextInputLayout;
import android.text.method.ScrollingMovementMethod;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Scanner;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import org.json.JSONArray;
import org.json.JSONObject;
public class MainActivity extends AppCompatActivity {

    String apiKey = getString(R.string.phishing_api_key);
    String safeBrowsingUrl = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + apiKey;


    private TextInputLayout urlInputLayout;
    private EditText urlInput;
    private Button checkButton, reportButton;
    private TextView resultText, threatLevelText;
    private ProgressBar progressBar;
    private TextView threatDetailsText;
    private CardView resultCard;
    private ImageView appLogo;
    private final Executor executor = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        String apiKey = getString(R.string.phishing_api_key);
        Log.d("API_KEY", "Retrieved API Key: " + apiKey);


        initializeViews();
        setupListeners();
        handleIntentData();
        applyAnimations();
    }

    @SuppressLint("WrongViewCast")
    private void initializeViews() {
        urlInputLayout = findViewById(R.id.urlInputLayout);
        urlInput = findViewById(R.id.urlInput);
        checkButton = findViewById(R.id.checkButton);
        progressBar = findViewById(R.id.progressBar);
        resultCard = findViewById(R.id.resultCard);
        threatLevelText = findViewById(R.id.threatLevelText);
        reportButton = findViewById(R.id.reportButton);
        threatDetailsText = findViewById(R.id.threatDetailsText);
        resultText = findViewById(R.id.resultText);
        appLogo = findViewById(R.id.appLogo);

        resultCard.setVisibility(View.GONE);
        threatDetailsText.setVisibility(View.GONE);
        progressBar.setVisibility(View.GONE);

        // Set app background color
        GradientDrawable gradientDrawable = new GradientDrawable(
                GradientDrawable.Orientation.TOP_BOTTOM,
                new int[]{Color.parseColor("#6200EE"), Color.parseColor("#3700B3")}
        );
        getWindow().getDecorView().setBackgroundColor(Color.parseColor("#F5F5F5"));

        // Apply modern UI enhancements
        GradientDrawable cardBackground = new GradientDrawable();
        cardBackground.setColor(Color.WHITE);
        cardBackground.setCornerRadius(25f);
        resultCard.setBackground(cardBackground);

        checkButton.setBackgroundColor(Color.parseColor("#6200EE"));
        checkButton.setTextColor(Color.WHITE);
        reportButton.setBackgroundColor(Color.RED);
        reportButton.setTextColor(Color.WHITE);
    }

    private void setupListeners() {
        checkButton.setOnClickListener(v -> {
            String url = urlInput.getText().toString().trim();
            if (validateInput(url)) {
                startUrlAnalysis(url);
            }
        });

        reportButton.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://www.antiphishing.org/report-phishing/"));
            startActivity(intent);
        });
    }

    private void applyAnimations() {
        Animation fadeIn = AnimationUtils.loadAnimation(this, R.anim.fade_in);
        Animation bounce = AnimationUtils.loadAnimation(this, R.anim.bounce);

        appLogo.startAnimation(fadeIn);
        checkButton.startAnimation(bounce);
        reportButton.startAnimation(bounce);
    }

    private void handleIntentData() {
        Intent intent = getIntent();
        if (intent != null) {
            String action = intent.getAction();
            String type = intent.getType();
            if (Intent.ACTION_SEND.equals(action) && "text/plain".equals(type)) {
                String sharedText = intent.getStringExtra(Intent.EXTRA_TEXT);
                if (sharedText != null) {
                    urlInput.setText(sharedText);
                }
            }
        }
    }
    private boolean validateInput(String url) {
        if (TextUtils.isEmpty(url)) {
            urlInputLayout.setError("Please enter a URL");
            return false;
        }
        if (!android.util.Patterns.WEB_URL.matcher(url).matches()) {
            urlInputLayout.setError("Please enter a valid URL");
            return false;
        }
        urlInputLayout.setError(null);
        return true;
    }

    private void startUrlAnalysis(String url) {
        progressBar.setVisibility(View.VISIBLE);
        resultCard.setVisibility(View.GONE);
        threatDetailsText.setVisibility(View.GONE);
        checkButton.setEnabled(false);

        executor.execute(() -> {
            boolean isSuspicious = analyzeUrl(url);
            runOnUiThread(() -> {
                displayResults(isSuspicious);
                progressBar.setVisibility(View.GONE);
                checkButton.setEnabled(true);
            });
        });
    }

    private boolean analyzeUrl(String url) {
        return url.contains("login") || url.contains("secure") || url.length() > 100;
    }

    private boolean checkWithGoogleSafeBrowsing(String urlStr) {
        try {
            JSONObject requestData = new JSONObject();
            JSONObject client = new JSONObject();
            client.put("clientId", "your company");
            client.put("clientVersion", "1.5.2");

            JSONArray threatEntries = new JSONArray();
            JSONObject urlEntry = new JSONObject();
            urlEntry.put("url", urlStr);
            threatEntries.put(urlEntry);

            JSONObject threatInfo = new JSONObject();
            threatInfo.put("threatTypes", new JSONArray().put("MALWARE").put("SOCIAL_ENGINEERING"));
            threatInfo.put("platformTypes", new JSONArray().put("ANY_PLATFORM"));
            threatInfo.put("threatEntryTypes", new JSONArray().put("URL"));
            threatInfo.put("threatEntries", threatEntries);

            requestData.put("client", client);
            requestData.put("threatInfo", threatInfo);

            URL url = new URL(safeBrowsingUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            OutputStream os = conn.getOutputStream();
            os.write(requestData.toString().getBytes());
            os.close();

            Scanner scanner = new Scanner(conn.getInputStream());
            String response = scanner.useDelimiter("\\A").hasNext() ? scanner.next() : "";
            scanner.close();

            return response.contains("matches"); // Only mark as suspicious if Google Safe Browsing flags it

        } catch (Exception e) {
            Log.e("MainActivity", "Error checking URL: " + e.getMessage());
            return false; // Default to not suspicious if there's an error
        }
    }


    private void displayResults(boolean isSuspicious) {
        resultCard.setVisibility(View.VISIBLE);
        resultCard.startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_in));

        if (isSuspicious) {
            threatLevelText.setText("⚠️ Suspicious");
            threatLevelText.setTextColor(Color.RED);
        } else {
            threatLevelText.setText("✔️ Not Suspicious");
            threatLevelText.setTextColor(Color.GREEN);
        }
    }
}
