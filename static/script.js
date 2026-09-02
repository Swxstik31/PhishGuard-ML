document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('url-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const resetBtn = document.getElementById('reset-btn');
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
    const modelInsights = document.getElementById('model-insights');
    const resInsights = document.getElementById('res-insights');
    
    // History DOM elements
    const historyList = document.getElementById('history-list');
    const clearHistoryBtn = document.getElementById('clear-history-btn');
    const histTotal = document.getElementById('hist-total');
    const histHigh = document.getElementById('hist-high');
    const histSusp = document.getElementById('hist-susp');
    const histLow = document.getElementById('hist-low');
    const sessionActivity = document.getElementById('session-activity');
    
    let featureImportanceData = [];
    let sessionCount = 0;
    const MAX_HISTORY = 50;
    
    // Report DOM elements
    const generateReportBtn = document.getElementById('generate-report-btn');
    const reportStatus = document.getElementById('report-status');
    window.currentAnalysisData = null;
    
    // Initialize History
    function getHistory() {
        try {
            const hist = localStorage.getItem('phishguard_history');
            return hist ? JSON.parse(hist) : [];
        } catch (e) {
            console.error("Corrupted history, resetting...", e);
            return [];
        }
    }
    
    function saveHistory(record) {
        let hist = getHistory();
        hist.unshift(record);
        if (hist.length > MAX_HISTORY) {
            hist = hist.slice(0, MAX_HISTORY);
        }
        localStorage.setItem('phishguard_history', JSON.stringify(hist));
        renderHistory();
    }
    
    function clearHistory() {
        if (confirm("Are you sure you want to clear your local prediction history?")) {
            localStorage.removeItem('phishguard_history');
            renderHistory();
        }
    }
    
    // Dashboard Elements
    const dashEmpty = document.getElementById('dash-empty-state');
    const dashContent = document.getElementById('dash-content');
    const dashSysStatus = document.getElementById('dash-sys-status');
    const dashStatusText = document.getElementById('dash-status-text');
    const dashTotal = document.getElementById('dash-total');
    const dashHigh = document.getElementById('dash-high');
    const dashSusp = document.getElementById('dash-susp');
    const dashLow = document.getElementById('dash-low');
    const barDanger = document.getElementById('bar-danger');
    const barWarning = document.getElementById('bar-warning');
    const barSafe = document.getElementById('bar-safe');
    const activityGraph = document.getElementById('activity-graph');
    const topSignalsList = document.getElementById('top-signals-list');

    function renderDashboard(hist) {
        if (hist.length === 0) {
            dashEmpty.classList.remove('hidden');
            dashContent.classList.add('hidden');
            return;
        }
        
        dashEmpty.classList.add('hidden');
        dashContent.classList.remove('hidden');
        
        let high = 0, susp = 0, low = 0;
        let riskFactorsCount = {};
        let activityByDate = {};
        
        // Build 7-day activity array
        const today = new Date();
        for(let i=6; i>=0; i--) {
            const d = new Date(today);
            d.setDate(today.getDate() - i);
            const dateStr = d.toISOString().split('T')[0];
            activityByDate[dateStr] = 0;
        }
        
        hist.forEach(record => {
            if (record.verdict === 'HIGH RISK') high++;
            else if (record.verdict === 'SUSPICIOUS') susp++;
            else low++;
            
            const dateStr = record.timestamp.split('T')[0];
            if (activityByDate[dateStr] !== undefined) {
                activityByDate[dateStr]++;
            }
            
            if (record.risk_factors_data) {
                record.risk_factors_data.forEach(rf => {
                    riskFactorsCount[rf] = (riskFactorsCount[rf] || 0) + 1;
                });
            }
        });
        
        const total = hist.length;
        dashTotal.textContent = total;
        dashHigh.textContent = high;
        dashSusp.textContent = susp;
        dashLow.textContent = low;
        
        // Status
        if (high > 0) {
            dashStatusText.textContent = "ATTENTION REQUIRED";
            dashStatusText.style.color = "var(--danger-color)";
            dashSysStatus.style.borderColor = "var(--danger-color)";
        } else {
            dashStatusText.textContent = "STABLE";
            dashStatusText.style.color = "var(--safe-color)";
            dashSysStatus.style.borderColor = "var(--border-color)";
        }
        
        // Distribution
        barDanger.style.width = (high / total * 100) + '%';
        barWarning.style.width = (susp / total * 100) + '%';
        barSafe.style.width = (low / total * 100) + '%';
        
        // Activity Graph
        activityGraph.innerHTML = '';
        let maxCount = Math.max(...Object.values(activityByDate));
        if (maxCount === 0) maxCount = 1;
        
        Object.keys(activityByDate).forEach(dateStr => {
            const count = activityByDate[dateStr];
            const height = Math.max((count / maxCount * 100), 2);
            
            const col = document.createElement('div');
            col.className = 'activity-col';
            col.style.height = height + '%';
            col.setAttribute('data-count', count);
            if(count > 0) col.style.background = 'var(--text-color)';
            
            activityGraph.appendChild(col);
        });
        
        // Top Signals
        topSignalsList.innerHTML = '';
        const sortedSignals = Object.keys(riskFactorsCount).map(key => ({
            name: key, count: riskFactorsCount[key]
        })).sort((a,b) => b.count - a.count).slice(0, 5);
        
        if (sortedSignals.length === 0) {
            topSignalsList.innerHTML = '<div style="opacity:0.6; font-size:0.8rem;">No risk signals detected in recent history.</div>';
        } else {
            sortedSignals.forEach(sig => {
                const row = document.createElement('div');
                row.className = 'signal-row';
                row.innerHTML = `
                    <span class="signal-name">${sig.name.replace(/_/g, ' ').toUpperCase()}</span>
                    <span class="signal-count">${sig.count}x</span>
                `;
                topSignalsList.appendChild(row);
            });
        }
    }
    
    function renderHistory() {
        const hist = getHistory();
        renderDashboard(hist);
        
        historyList.innerHTML = '';
        
        let high = 0, susp = 0, low = 0;
        
        if (hist.length === 0) {
            historyList.innerHTML = '<div class="empty-history">NO RECENT ANALYSES</div>';
        } else {
            hist.forEach((record, index) => {
                if (record.verdict === 'HIGH RISK') high++;
                else if (record.verdict === 'SUSPICIOUS') susp++;
                else low++;
                
                // Render top 10
                if (index < 10) {
                    const row = document.createElement('div');
                    row.className = 'history-row';
                    
                    let vClass = 'text-safe';
                    if (record.verdict === 'HIGH RISK') vClass = 'text-danger';
                    if (record.verdict === 'SUSPICIOUS') vClass = 'text-warning';
                    
                    const timeStr = new Date(record.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
                    
                    row.innerHTML = `
                        <div class="h-time">${timeStr}</div>
                        <div class="h-url" title="${record.url}">${record.url}</div>
                        <div class="h-verdict ${vClass}">${record.verdict}</div>
                        <div class="h-score">${record.risk_score}/100</div>
                    `;
                    historyList.appendChild(row);
                }
            });
        }
        
        histTotal.textContent = hist.length;
        histHigh.textContent = high;
        histSusp.textContent = susp;
        histLow.textContent = low;
    }
    
    clearHistoryBtn.addEventListener('click', clearHistory);
    
    // Fetch feature importance on load
    fetch('/feature-importance')
        .then(res => res.json())
        .then(data => {
            if(data.success && data.feature_importance) {
                featureImportanceData = data.feature_importance;
            }
        }).catch(err => console.error("Error loading feature importance:", err));
        
    // Initial render
    renderHistory();

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

    if (resetBtn) {
        resetBtn.addEventListener('click', (e) => {
            e.preventDefault();
            urlInput.value = '';
            hideResults();
        });
    }

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
            
            // Save to history and increment session counter
            sessionCount++;
            if (sessionActivity) {
                sessionActivity.textContent = `ACTIVITY: ${sessionCount}`;
            }
            saveHistory({
                timestamp: new Date().toISOString(),
                url: data.url,
                verdict: data.verdict,
                risk_score: data.risk_score,
                phishing_probability: data.phishing_probability,
                number_of_risk_factors: data.risk_factors ? data.risk_factors.length : 0,
                risk_factors_data: data.risk_factors ? data.risk_factors.map(rf => rf.feature) : []
            });
            
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
            window.currentAnalysisData = data;
            if(reportStatus) {
                reportStatus.classList.remove('visible');
                reportStatus.classList.add('hidden');
            }
            
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

            const resExplanationSummary = document.getElementById('res-explanation-summary');
            const resRiskFactors = document.getElementById('res-risk-factors');
            const explanationContainer = document.getElementById('explanation-container');
            
            if (data.explanation_summary) {
                resExplanationSummary.textContent = data.explanation_summary;
                explanationContainer.style.display = 'block';
            } else {
                explanationContainer.style.display = 'none';
            }
            
            resRiskFactors.innerHTML = '';
            if (data.risk_factors && Array.isArray(data.risk_factors)) {
                data.risk_factors.forEach(factor => {
                    const card = document.createElement('div');
                    card.className = 'risk-factor-card animate-in';
                    const formattedFeature = factor.feature.replace(/_/g, ' ').toUpperCase();
                    
                    card.innerHTML = `
                        <div class="rf-severity ${factor.severity}">${factor.severity}</div>
                        <div class="rf-content">
                            <span class="rf-feature">${formattedFeature} [${factor.value}]</span>
                            <span class="rf-explanation">${factor.explanation}</span>
                        </div>
                    `;
                    resRiskFactors.appendChild(card);
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
            
            // Render Model Insights if data exists
            if (featureImportanceData && featureImportanceData.length > 0) {
                resInsights.innerHTML = '';
                const topFeatures = featureImportanceData.slice(0, 3);
                
                topFeatures.forEach((factor, index) => {
                    const insightCard = document.createElement('div');
                    insightCard.className = 'insight-card animate-in';
                    const formattedName = factor.feature.replace(/_/g, ' ').toUpperCase();
                    
                    let dirText = factor.direction === 'increases_phishing_risk' ? 'Increases Risk' : 'Decreases Risk';
                    
                    insightCard.innerHTML = `
                        <div class="insight-rank">0${index + 1}</div>
                        <div class="insight-content">
                            <span class="insight-feature">${formattedName}</span>
                            <span class="insight-desc">Coefficient: ${factor.coefficient} (${dirText})</span>
                        </div>
                    `;
                    resInsights.appendChild(insightCard);
                });
                modelInsights.classList.remove('hidden');
            } else {
                modelInsights.classList.add('hidden');
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

    // Generate PDF Report
    if (generateReportBtn) {
        generateReportBtn.addEventListener('click', () => {
            const data = window.currentAnalysisData;
            if (!data) return;
            
            try {
                const { jsPDF } = window.jspdf;
                const doc = new jsPDF();
                const margin = 15;
                let yPos = margin;
                
                // HEADER
                doc.setFont("helvetica", "bold");
                doc.setFontSize(20);
                doc.text("PHISHGUARD-ML", margin, yPos);
                yPos += 8;
                doc.setFontSize(14);
                doc.setTextColor(100);
                doc.text("SECURITY ANALYSIS REPORT", margin, yPos);
                yPos += 15;
                
                // METADATA
                doc.setFont("helvetica", "normal");
                doc.setFontSize(10);
                doc.setTextColor(0);
                doc.text(`Date/Time: ${new Date().toLocaleString()}`, margin, yPos);
                yPos += 6;
                doc.text(`Analysis Engine: Logistic Regression (27 static lexical features)`, margin, yPos);
                yPos += 12;
                
                // URL (Truncated if too long)
                doc.setFont("helvetica", "bold");
                doc.text("SUBMITTED URL:", margin, yPos);
                yPos += 6;
                doc.setFont("helvetica", "normal");
                
                const splitUrl = doc.splitTextToSize(data.url || "N/A", 180);
                doc.text(splitUrl, margin, yPos);
                yPos += (splitUrl.length * 6) + 10;
                
                // VERDICT BOX
                doc.setFillColor(245, 245, 245);
                doc.rect(margin, yPos, 180, 25, 'F');
                doc.setFont("helvetica", "bold");
                doc.text("VERDICT: " + (data.verdict || "UNKNOWN"), margin + 5, yPos + 8);
                doc.text("RISK SCORE: " + (data.risk_score || 0) + "/100", margin + 5, yPos + 15);
                doc.text("PHISHING PROBABILITY: " + (data.phishing_probability || 0) + "%", margin + 5, yPos + 22);
                yPos += 35;
                
                // WHY IT WAS FLAGGED
                if (data.explanation_summary) {
                    doc.setFont("helvetica", "bold");
                    doc.text("WHY WAS THIS URL FLAGGED?", margin, yPos);
                    yPos += 6;
                    doc.setFont("helvetica", "normal");
                    const summary = doc.splitTextToSize(data.explanation_summary, 180);
                    doc.text(summary, margin, yPos);
                    yPos += (summary.length * 5) + 5;
                }
                
                if (data.risk_factors && data.risk_factors.length > 0) {
                    data.risk_factors.forEach(rf => {
                        const rfText = doc.splitTextToSize(`- [${rf.severity.toUpperCase()}] ${rf.feature.toUpperCase()}: ${rf.explanation}`, 180);
                        doc.text(rfText, margin, yPos);
                        yPos += (rfText.length * 5) + 2;
                    });
                    yPos += 5;
                }
                
                // TOP MODEL SIGNALS (Insights)
                if (featureImportanceData && featureImportanceData.length > 0) {
                    // Check page height
                    if (yPos > 240) { doc.addPage(); yPos = margin; }
                    
                    doc.setFont("helvetica", "bold");
                    doc.text("TOP MODEL SIGNALS", margin, yPos);
                    yPos += 6;
                    doc.setFont("helvetica", "normal");
                    const topFeatures = featureImportanceData.slice(0, 3);
                    topFeatures.forEach((factor, idx) => {
                        let dirText = factor.direction === 'increases_phishing_risk' ? 'Increases Risk' : 'Decreases Risk';
                        doc.text(`0${idx+1}. ${factor.feature.toUpperCase()} (Coefficient: ${factor.coefficient}, ${dirText})`, margin, yPos);
                        yPos += 6;
                    });
                    yPos += 10;
                }
                
                // EXTRACTED FEATURES TABLE
                if (data.extracted_features) {
                    // Check page height
                    if (yPos > 200) { doc.addPage(); yPos = margin; }
                    
                    doc.setFont("helvetica", "bold");
                    doc.text("EXTRACTED URL FEATURES", margin, yPos);
                    yPos += 5;
                    
                    const tableData = [];
                    for (const [key, val] of Object.entries(data.extracted_features)) {
                        tableData.push([key, val.toString()]);
                    }
                    
                    doc.autoTable({
                        startY: yPos,
                        head: [['Feature', 'Extracted Value']],
                        body: tableData,
                        theme: 'striped',
                        headStyles: { fillColor: [40, 40, 40] },
                        margin: { left: margin, right: margin }
                    });
                    
                    yPos = doc.lastAutoTable.finalY + 15;
                }
                
                // DISCLAIMER
                if (yPos > 270) { doc.addPage(); yPos = margin; }
                doc.setFont("helvetica", "italic");
                doc.setFontSize(8);
                doc.setTextColor(100);
                const disclaimer = doc.splitTextToSize("DISCLAIMER: This analysis evaluates characteristics of the submitted URL as text. It does not guarantee that a URL is safe or malicious and does not replace professional security analysis.", 180);
                doc.text(disclaimer, margin, yPos);
                
                // Save PDF
                doc.save(`Security_Report_${Date.now()}.pdf`);
                
                reportStatus.classList.remove('hidden');
                reportStatus.classList.add('visible');
                
            } catch (err) {
                console.error("PDF Generation Error:", err);
                alert("Failed to generate PDF report.");
            }
        });
    }
