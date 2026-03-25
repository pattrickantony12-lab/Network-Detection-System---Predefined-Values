// Real-time monitoring JavaScript

let trafficChart, threatChart;
let trafficLabels = [];
let trafficData = [];
let threatData = [];
let packetsData = [];
let updateInterval;

function initRealtimeCharts() {
    // Traffic Chart
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: trafficLabels,
            datasets: [{
                label: 'Packets/sec',
                data: trafficData,
                borderColor: 'rgb(75, 192, 192)',
                backgroundColor: 'rgba(75, 192, 192, 0.1)',
                borderWidth: 2,
                tension: 0.1,
                fill: true
            }]
        },
        options: {
            responsive: true,
            animation: {
                duration: 0 // Disable animation for real-time updates
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Packets'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Time'
                    }
                }
            }
        }
    });

    // Threat Distribution Chart
    const threatCtx = document.getElementById('threatChart').getContext('2d');
    threatChart = new Chart(threatCtx, {
        type: 'doughnut',
        data: {
            labels: ['Malicious', 'Suspicious', 'Normal'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.8)',
                    'rgba(255, 205, 86, 0.8)',
                    'rgba(75, 192, 192, 0.8)'
                ],
                borderColor: [
                    'rgb(255, 99, 132)',
                    'rgb(255, 205, 86)',
                    'rgb(75, 192, 192)'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            let label = context.label || '';
                            if (label) {
                                label += ': ';
                            }
                            label += context.parsed;
                            return label;
                        }
                    }
                }
            }
        }
    });
}

function updateMonitoringData() {
    fetch('/api/monitoring-data')
        .then(response => response.json())
        .then(data => {
            // Update stats
            document.getElementById('totalPackets').textContent =
                data.stats.packets_processed;
            document.getElementById('maliciousPackets').textContent =
                data.stats.malicious_packets;
            document.getElementById('suspiciousPackets').textContent =
                data.stats.suspicious_packets;
            document.getElementById('normalPackets').textContent =
                data.stats.normal_packets;
            document.getElementById('cpuUsage').textContent =
                data.stats.cpu_usage.toFixed(1) + '%';
            document.getElementById('memoryUsage').textContent =
                data.stats.memory_usage.toFixed(1) + '%';

            // Update traffic chart
            const trafficDataPoints = data.traffic_data;
            if (trafficDataPoints.length > 0) {
                trafficLabels = trafficDataPoints.map(d => d.time);
                trafficData = trafficDataPoints.map(d => d.packets || d.traffic || 0);

                if (trafficChart) {
                    trafficChart.data.labels = trafficLabels.slice(-20); // Last 20 points
                    trafficChart.data.datasets[0].data = trafficData.slice(-20);
                    trafficChart.update('none');
                }
            }

            // Update threat chart
            if (threatChart) {
                threatChart.data.datasets[0].data = [
                    data.stats.malicious_packets,
                    data.stats.suspicious_packets,
                    data.stats.normal_packets
                ];
                threatChart.update();
            }

            // Update packet stream
            updatePacketStream(data.packets);

            // Update alerts
            updateAlerts(data.alerts);

            // Update last update time
            document.getElementById('lastUpdateTime').textContent =
                data.stats.last_update;
        })
        .catch(error => {
            console.error('Error fetching monitoring data:', error);
            addSystemLog('Error fetching monitoring data: ' + error.message, 'error');
        });
}

function updatePacketStream(packets) {
    const packetStream = document.getElementById('packetStream');
    let html = '';

    if (packets && packets.length > 0) {
        // Reverse to show newest first
        packets.slice().reverse().forEach(packet => {
            let severityClass = 'packet-normal';
            let severityIcon = '✅';

            if (packet.attack_type && packet.attack_type.toLowerCase().includes('dos')) {
                severityClass = 'packet-malicious';
                severityIcon = '🚨';
            } else if (packet.confidence > 50 && packet.confidence <= 70) {
                severityClass = 'packet-suspicious';
                severityIcon = '⚠️';
            }

            html += `
                <div class="packet-item ${severityClass}">
                    <div class="packet-header">
                        <span class="packet-number">#${packet.packet_number}</span>
                        <span class="packet-time">${packet.timestamp}</span>
                        <span class="packet-severity">${severityIcon} ${packet.attack_type || 'Unknown'}</span>
                    </div>
                    <div class="packet-details">
                        <span class="packet-source">${packet.source_ip || 'N/A'}:${packet.source_port || 'N/A'}</span>
                        <span class="packet-arrow">→</span>
                        <span class="packet-dest">${packet.destination_ip || 'N/A'}:${packet.destination_port || 'N/A'}</span>
                        <span class="packet-protocol">${packet.protocol || 'N/A'}</span>
                        <span class="packet-size">${packet.packet_size || 0} bytes</span>
                    </div>
                    <div class="packet-footer">
                        <span class="packet-confidence">Confidence: ${packet.confidence ? packet.confidence.toFixed(1) : 'N/A'}%</span>
                    </div>
                </div>
            `;
        });
    } else {
        html = '<div class="packet-placeholder"><p>No packets processed yet. Start monitoring to see live packet analysis.</p></div>';
    }

    packetStream.innerHTML = html;
}

function updateAlerts(alerts) {
    const alertsContainer = document.getElementById('alertsContainer');
    let html = '';

    if (alerts && alerts.length > 0) {
        alerts.slice().reverse().forEach(alert => {
            let severityClass = 'alert-low';
            let severityIcon = 'ℹ️';

            switch(alert.severity.toLowerCase()) {
                case 'critical':
                    severityClass = 'alert-critical';
                    severityIcon = '🔥';
                    break;
                case 'high':
                    severityClass = 'alert-high';
                    severityIcon = '🚨';
                    break;
                case 'medium':
                    severityClass = 'alert-medium';
                    severityIcon = '⚠️';
                    break;
                case 'low':
                    severityClass = 'alert-low';
                    severityIcon = 'ℹ️';
                    break;
            }

            html += `
                <div class="alert-item ${severityClass}">
                    <div class="alert-header">
                        <span class="alert-icon">${severityIcon}</span>
                        <span class="alert-type">${alert.type}</span>
                        <span class="alert-time">${alert.timestamp}</span>
                    </div>
                    <div class="alert-body">
                        <p>${alert.description}</p>
                        <div class="alert-details">
                            <span>Source: ${alert.source}</span>
                            <span>Destination: ${alert.destination}</span>
                            ${alert.confidence ? `<span>Confidence: ${alert.confidence.toFixed(1)}%</span>` : ''}
                        </div>
                    </div>
                </div>
            `;
        });
    } else {
        html = '<div class="no-alerts">No security alerts at the moment.</div>';
    }

    alertsContainer.innerHTML = html;
}

function startMonitoring() {
    fetch('/api/start-monitoring')
        .then(response => response.json())
        .then(data => {
            updateMonitoringStatus();
            addSystemLog('Monitoring started: ' + data.message, 'success');
        })
        .catch(error => {
            console.error('Error starting monitoring:', error);
            addSystemLog('Error starting monitoring: ' + error.message, 'error');
        });
}

function stopMonitoring() {
    fetch('/api/stop-monitoring')
        .then(response => response.json())
        .then(data => {
            updateMonitoringStatus();
            addSystemLog('Monitoring stopped: ' + data.message, 'info');
        })
        .catch(error => {
            console.error('Error stopping monitoring:', error);
            addSystemLog('Error stopping monitoring: ' + error.message, 'error');
        });
}

function clearPacketData() {
    if (confirm('Are you sure you want to clear all packet data?')) {
        fetch('/api/clear-packets')
            .then(response => response.json())
            .then(data => {
                updateMonitoringData();
                addSystemLog('Packet data cleared', 'info');
            })
            .catch(error => {
                console.error('Error clearing packets:', error);
                addSystemLog('Error clearing packets: ' + error.message, 'error');
            });
    }
}

function updateMonitoringStatus() {
    fetch('/api/monitoring-status')
        .then(response => response.json())
        .then(data => {
            const statusElement = document.getElementById('monitoringStatus');
            const startBtn = document.getElementById('startMonitoring');
            const stopBtn = document.getElementById('stopMonitoring');

            if (data.sniffing_active) {
                statusElement.textContent = 'Active ✅';
                statusElement.className = 'status-value status-success';
                startBtn.disabled = true;
                stopBtn.disabled = false;
            } else {
                statusElement.textContent = 'Inactive ⚠️';
                statusElement.className = 'status-value status-error';
                startBtn.disabled = false;
                stopBtn.disabled = true;
            }

            // Update stats
            document.getElementById('totalPackets').textContent = data.packets_processed;
            document.getElementById('maliciousPackets').textContent = data.malicious_packets;
            document.getElementById('suspiciousPackets').textContent = data.suspicious_packets;
            document.getElementById('normalPackets').textContent = data.normal_packets;
        })
        .catch(error => {
            console.error('Error updating monitoring status:', error);
        });
}

function filterPackets() {
    const filterText = document.getElementById('packetFilter').value.toLowerCase();
    const severityFilter = document.getElementById('severityFilter').value;

    const packetItems = document.querySelectorAll('.packet-item');

    packetItems.forEach(item => {
        const packetText = item.textContent.toLowerCase();
        const packetSeverity = item.classList.contains('packet-malicious') ? 'malicious' :
                              item.classList.contains('packet-suspicious') ? 'suspicious' : 'normal';

        const matchesText = filterText === '' || packetText.includes(filterText);
        const matchesSeverity = severityFilter === 'all' || packetSeverity === severityFilter;

        if (matchesText && matchesSeverity) {
            item.style.display = 'block';
        } else {
            item.style.display = 'none';
        }
    });
}

function addSystemLog(message, type = 'info') {
    const logsContainer = document.getElementById('systemLogs');
    const now = new Date();
    const timeString = now.toLocaleTimeString();

    let typeIcon = 'ℹ️';
    let typeClass = 'log-info';

    switch(type) {
        case 'success':
            typeIcon = '✅';
            typeClass = 'log-success';
            break;
        case 'error':
            typeIcon = '❌';
            typeClass = 'log-error';
            break;
        case 'warning':
            typeIcon = '⚠️';
            typeClass = 'log-warning';
            break;
    }

    const logEntry = document.createElement('div');
    logEntry.className = `log-entry ${typeClass}`;
    logEntry.innerHTML = `
        <span class="log-time">${timeString}</span>
        <span class="log-icon">${typeIcon}</span>
        <span class="log-message">${message}</span>
    `;

    logsContainer.insertBefore(logEntry, logsContainer.firstChild);

    // Keep only last 50 logs
    const logs = logsContainer.querySelectorAll('.log-entry');
    if (logs.length > 50) {
        logs[logs.length - 1].remove();
    }
}

function startRealTimeUpdates() {
    updateMonitoringData();
    updateInterval = setInterval(updateMonitoringData, 2000); // Update every 2 seconds
}

function stopRealTimeUpdates() {
    if (updateInterval) {
        clearInterval(updateInterval);
    }
}

// Clean up on page unload
window.addEventListener('beforeunload', stopRealTimeUpdates);