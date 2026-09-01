document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('url-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const btnText = analyzeBtn.querySelector('.btn-text');
    const errorMsg = document.getElementById('error-message');
    const resultsSection = document.getElementById('results-section');
    const demoBtns = document.querySelectorAll('.demo-btn');

    const resScoreValue = document.getElementById('res-score-value');
    const scoreProgress = document.getElementById('score-progress');
    const resVerdict = document.getElementById('res-verdict');
    const resVerdictSub = document.getElementById('res-verdict-sub');
    const scoreCard = document.getElementById('score-card');
    const resProb = document.getElementById('res-prob');
    const resVerdictSm = document.getElementById('res-verdict-sm');
    const resIndicators = document.getElementById('res-indicators');
    const resFeatures = document.getElementById('res-features');

    urlInput.addEventListener('focus', () => {
        if(window.innerWidth > 600) {
            urlInput.parentElement.style.transform = 'translateY(-2px)';
        }
    });
    urlInput.addEventListener('blur', () => {
        urlInput.parentElement.style.transform = 'none';
    });

    demoBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            urlInput.value = btn.dataset.url;
            hideResults();
        });
    });

    analyzeBtn.addEventListener('click', (e) => {
        e.preventDefault();
        analyzeUrl();
    });
    
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            analyzeUrl();
        }
    });

    function hideResults() {
        resultsSection.classList.remove('visible');
        errorMsg.classList.add('hidden');
        resultsSection.classList.add('hidden');
        if(scoreProgress) scoreProgress.style.strokeDashoffset = 283;
    }

    async function analyzeUrl() {
        const url = urlInput.value.trim();
        if (!url) {
            showError('ERROR: NO URL PROVIDED');
            return;
        }

        hideResults();
        analyzeBtn.disabled = true;
        analyzeBtn.classList.add('loading');
        btnText.textContent = 'ANALYZING...';

        try {
            const response = await fetch('/predict', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });
            
            const data = await response.json();
            
            if (!data.success) {
                throw new Error(data.error || 'SERVER ERROR OCCURRED');
            }
            
            displayResults(data);
            
        } catch (error) {
            console.error("Analysis Error:", error);
            showError(error.message ? error.message.toUpperCase() : "ANALYSIS FAILED\nUNABLE TO ANALYZE THIS URL.");
        } finally {
            analyzeBtn.disabled = false;
            analyzeBtn.classList.remove('loading');
            btnText.textContent = 'ANALYZE URL';
        }
    }

    function animateValue(obj, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            const easeProgress = 1 - Math.pow(1 - progress, 4);
            obj.innerHTML = Math.floor(easeProgress * (end - start) + start);
            if (progress < 1) {
                window.requestAnimationFrame(step);
            } else {
                obj.innerHTML = end;
            }
        };
        window.requestAnimationFrame(step);
    }

    function displayResults(data) {
        try {
            scoreCard.className = 'score-card';
            resultsSection.classList.remove('risk-low', 'risk-suspicious', 'risk-high', 'hidden');
            
            void resultsSection.offsetWidth; // force reflow

            let riskClass = '';
            if (data.verdict === 'LOW RISK' || data.risk_score <= 30) {
                riskClass = 'risk-low';
                resVerdictSub.textContent = 'APPEARS SAFE';
            } else if (data.verdict === 'SUSPICIOUS' || data.risk_score <= 70) {
                riskClass = 'risk-suspicious';
                resVerdictSub.textContent = 'PROCEED WITH CAUTION';
            } else {
                riskClass = 'risk-high';
                resVerdictSub.textContent = 'POSSIBLE PHISHING';
            }
            
            resultsSection.classList.add(riskClass);
            scoreCard.classList.add(riskClass);

            resVerdict.textContent = data.verdict;
            resProb.textContent = data.phishing_probability + '%';
            resVerdictSm.textContent = data.verdict;

            resIndicators.innerHTML = '';
            if(data.security_indicators && Array.isArray(data.security_indicators)) {
                data.security_indicators.forEach((ind, index) => {
                    const isWarning = ind.startsWith('⚠');
                    const isCritical = ind.includes('not enabled') || ind.includes('IP address') || ind.includes('Suspicious keyword');
                    
                    let statusClass = 'status-safe';
                    let icon = isWarning ? '⚠' : '✓';
                    
                    let name = ind.length > 2 ? ind.substring(2).trim() : ind;

                    if (isWarning) {
                        statusClass = isCritical ? 'status-danger' : 'status-warning';
                        icon = '●';
                    } else {
                        icon = '●';
                    }

                    const row = document.createElement('div');
                    row.className = 'indicator-row animate-in';
                    
                    row.innerHTML = `
                        <span class="indicator-dot ${statusClass}">${icon}</span>
                        <span class="indicator-name">${name.toUpperCase()}</span>
                        <span class="indicator-status ${statusClass}">${isWarning ? 'DETECTED' : 'NOT DETECTED'}</span>
                    `;
                    resIndicators.appendChild(row);
                });
            }

            resFeatures.innerHTML = '';
            if(data.extracted_features) {
                for (const [key, val] of Object.entries(data.extracted_features)) {
                    let formattedKey = key.replace(/_/g, ' ').toUpperCase();
                    if (formattedKey === 'NUM DOTS') formattedKey = 'DOT COUNT';
                    if (formattedKey === 'NUM HYPHENS') formattedKey = 'HYPHEN COUNT';
                    if (formattedKey === 'NUM SPECIAL CHARS') formattedKey = 'SPECIAL CHARACTERS';
                    if (formattedKey === 'HAS HTTPS') formattedKey = 'HTTPS';
                    
                    let displayVal = val;
                    if (typeof val === 'number' && (val === 0 || val === 1) && (key.startsWith('has_') || key.startsWith('is_'))) {
                        displayVal = val === 1 ? 'YES' : 'NO';
                    }

                    const item = document.createElement('div');
                    item.className = 'feature-item animate-in';
                    
                    item.innerHTML = `
                        <span class="feature-label">${formattedKey}</span>
                        <span class="feature-val">${displayVal}</span>
                    `;
                    resFeatures.appendChild(item);
                }
            }

            requestAnimationFrame(() => {
                resultsSection.classList.add('visible');
                
                setTimeout(() => {
                    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }, 50);

                animateValue(resScoreValue, 0, data.risk_score || 0, 1000);

                setTimeout(() => {
                    const offset = 283 - ((data.risk_score || 0) / 100) * 283;
                    if(scoreProgress) scoreProgress.style.strokeDashoffset = offset;
                }, 100);
            });
            
        } catch(err) {
            console.error("Display Error:", err);
            showError("ANALYSIS FAILED\nUNABLE TO DISPLAY RESULTS.");
        }
    }

    function showError(message) {
        errorMsg.textContent = message;
        errorMsg.classList.remove('hidden');
        resultsSection.classList.remove('visible');
        resultsSection.classList.add('hidden');
    }
});
