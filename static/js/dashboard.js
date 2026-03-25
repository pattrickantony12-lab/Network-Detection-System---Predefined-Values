// Dashboard functionality
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    initTooltips();

    // Load user stats
    loadUserStats();
});

function initTooltips() {
    const tooltips = document.querySelectorAll('[data-tooltip]');
    tooltips.forEach(element => {
        element.addEventListener('mouseenter', showTooltip);
        element.addEventListener('mouseleave', hideTooltip);
    });
}

function showTooltip(e) {
    const tooltipText = e.target.getAttribute('data-tooltip');
    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip';
    tooltip.textContent = tooltipText;
    document.body.appendChild(tooltip);

    const rect = e.target.getBoundingClientRect();
    tooltip.style.left = rect.left + 'px';
    tooltip.style.top = (rect.top - tooltip.offsetHeight - 10) + 'px';
}

function hideTooltip() {
    const tooltip = document.querySelector('.tooltip');
    if (tooltip) {
        tooltip.remove();
    }
}

function loadUserStats() {
    fetch('/api/user-stats')
        .then(response => response.json())
        .then(data => {
            updateStatsCharts(data);
        })
        .catch(error => console.error('Error loading user stats:', error));
}

function updateStatsCharts(stats) {
    // Update threat distribution chart
    if (document.getElementById('threatChart')) {
        const threatCtx = document.getElementById('threatChart').getContext('2d');
        new Chart(threatCtx, {
            type: 'doughnut',
            data: {
                labels: ['Normal', 'Suspicious', 'Malicious'],
                datasets: [{
                    data: [stats.normal, stats.suspicious, stats.malicious],
                    backgroundColor: [
                        '#28a745',
                        '#ffc107',
                        '#dc3545'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    // Update activity chart
    if (document.getElementById('activityChart')) {
        const activityCtx = document.getElementById('activityChart').getContext('2d');
        const today = new Date();
        const labels = [];
        const data = [];

        // Generate last 7 days data
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(today.getDate() - i);
            labels.push(date.toLocaleDateString('en-US', { weekday: 'short' }));
            data.push(Math.floor(Math.random() * 50) + 10); // Simulated data
        }

        new Chart(activityCtx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Daily Scans',
                    data: data,
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
}

// Network data validation
function validateNetworkData(input) {
    if (!input.trim()) {
        return 'Please enter network data';
    }

    // Basic validation - check for common network data patterns
    const lines = input.trim().split('\n');
    if (lines.length < 3) {
        return 'Please enter more detailed network data';
    }

    return null;
}

// Export data functionality
function exportScanHistory() {
    fetch('/api/export-history')
        .then(response => response.json())
        .then(data => {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'scan-history-' + new Date().toISOString().split('T')[0] + '.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        })
        .catch(error => console.error('Error exporting data:', error));
}

// Real-time update for monitoring page
function startRealTimeUpdates() {
    if (window.location.pathname.includes('monitoring')) {
        setInterval(updateMonitoringWidgets, 5000);
    }
}

function updateMonitoringWidgets() {
    // Update any real-time widgets on the page
    const widgets = document.querySelectorAll('.real-time-widget');
    widgets.forEach(widget => {
        // Update widget data
        const randomValue = Math.floor(Math.random() * 100);
        widget.querySelector('.value').textContent = randomValue;
    });
}

// Initialize real-time updates
startRealTimeUpdates();