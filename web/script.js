document.addEventListener('DOMContentLoaded', () => {
    // --- Variable declarations ---
    const welcomeScreen = document.getElementById('welcome-screen');
    const loginFormContainer = document.getElementById('login-form-container');
    const registerFormContainer = document.getElementById('register-form-container');
    const showLoginBtn = document.getElementById('show-login-btn');
    const showRegisterBtn = document.getElementById('show-register-btn');
    const loginUsernameInput = document.getElementById('login-username');
    const loginPasswordInput = document.getElementById('login-password');
    const loginBtnAction = document.getElementById('login-btn-action');
    const loginError = document.getElementById('login-error');
    const registerUsernameInput = document.getElementById('register-username');
    const registerPasswordInput = document.getElementById('register-password');
    const registerCodeInput = document.getElementById('register-code');
    const registerBtn = document.getElementById('register-btn');
    const registerMessage = document.getElementById('register-message');
    const splashScreen = document.getElementById('splash-screen');
    const mainDashboard = document.getElementById('main-dashboard');
    const displayFilterInput = document.getElementById('display-filter-input');
    const bpfFilter = document.getElementById('bpf-filter');
    const toggleSniffBtn = document.getElementById('toggle-sniff-btn');
    const clearAllBtn = document.getElementById('clear-all-btn');
    const saveAllPcapBtn = document.getElementById('save-all-pcap-btn');
    const exportCredsTxtBtn = document.getElementById('export-creds-txt-btn');
    const packetTableBody = document.getElementById('packet-table-body');
    const credentialsContainer = document.getElementById('credentials-container');
    const credentialsTabBtn = document.getElementById('credentials-tab-btn');
    const packetCountEl = document.getElementById('packet-count');
    const statusText = document.getElementById('status-text');
    const statusIndicator = document.getElementById('status-indicator');
    const credCountBadge = document.getElementById('cred-count-badge');
    const packetDetailModal = document.getElementById('packet-detail-modal');
    const packetDetailContent = document.getElementById('packet-detail-content');
    const mainContent = document.querySelector('.main-content');
    const confirmModal = document.getElementById('confirm-modal');
    const confirmDeleteBtn = document.getElementById('confirm-delete-btn');
    const cancelDeleteBtn = document.getElementById('cancel-delete-btn');
    const selectWrapper = document.getElementById('custom-select-wrapper');
    const selectTrigger = document.getElementById('select-trigger');
    const selectItemsContainer = document.getElementById('select-items-container');
    const statPacketCount = document.getElementById('stat-packet-count');
    const statCredCount = document.getElementById('stat-cred-count');
    const topProtocolsList = document.getElementById('top-protocols-list');
    const topPortsList = document.getElementById('top-ports-list');
    const sessionNameDisplay = document.getElementById('session-name-display');
    const sessionNameInput = document.getElementById('session-name-input');
    const editNameBtn = document.getElementById('edit-name-btn');
    const saveNameBtn = document.getElementById('save-name-btn');
    const tableContainer = document.querySelector('.table-container'); // For scroll detection

    let packetCount = 0;
    let credCount = 0;
    let interfaces = {};
    let allPacketIds = [];
    let isSniffing = false;
    let filterTimeout;
    let selectedInterfaceGuid = null;
    let protoStats = {};
    let portStats = {};

    // --- NEW: Variables for infinite scroll ---
    let isLoadingMore = false;
    let currentOffset = 0;
    const PACKET_PAGE_SIZE = 100; // How many packets to load per scroll
    let noMorePacketsToLoad = false;

    showLoginBtn.addEventListener('click', () => {
        loginFormContainer.style.display = 'flex';
        registerFormContainer.style.display = 'none';
        showLoginBtn.classList.add('active');
        showRegisterBtn.classList.remove('active');
    });
    showRegisterBtn.addEventListener('click', () => {
        loginFormContainer.style.display = 'none';
        registerFormContainer.style.display = 'flex';
        showLoginBtn.classList.remove('active');
        showRegisterBtn.classList.add('active');
    });
    loginBtnAction.addEventListener('click', async () => {
        const username = loginUsernameInput.value;
        const password = loginPasswordInput.value;
        const result = await eel.login_user(username, password)();
        if (result.status === 'success') {
            loginError.className = 'form-message success';
            loginError.textContent = result.message;
            setTimeout(loginSuccess, 1000);
        } else {
            loginError.className = 'form-message error';
            loginError.textContent = result.message;
        }
    });
    registerBtn.addEventListener('click', async () => {
        const username = registerUsernameInput.value;
        const password = registerPasswordInput.value;
        const code = registerCodeInput.value;
        const result = await eel.register_user(username, password, code)();
        registerMessage.className = `form-message ${result.status}`;
        registerMessage.textContent = result.message;
    });

    if (clearAllBtn) {
        clearAllBtn.addEventListener('click', () => { confirmModal.style.display = 'flex'; });
    }
    confirmDeleteBtn.addEventListener('click', async () => {
        await clearAllData(); // Make it async
        confirmModal.style.display = 'none';
    });
    cancelDeleteBtn.addEventListener('click', () => {
        confirmModal.style.display = 'none';
    });
    confirmModal.addEventListener('click', (e) => {
        if (e.target === confirmModal) { confirmModal.style.display = 'none'; }
    });

    document.querySelectorAll('.quick-filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            bpfFilter.value = btn.dataset.filter;
            document.querySelectorAll('.quick-filter-btn').forEach(b => b.classList.remove('selected'));
            btn.classList.add('selected');
            statusText.innerText = `Capture filter: ${btn.querySelector('.text').textContent}`;
            setTimeout(() => {
                if(!isSniffing) statusText.innerText = 'Status: Ready';
            }, 3000);
        });
    });

    function setupModalCloseListeners() {
        const modalCloseBtn = packetDetailModal.querySelector('.modal-close');
        if(modalCloseBtn) {
            modalCloseBtn.addEventListener('click', () => { packetDetailModal.style.display = 'none'; });
        }
        packetDetailModal.addEventListener('click', (e) => {
            if (e.target === packetDetailModal) { packetDetailModal.style.display = 'none'; }
        });
    }
    setupModalCloseListeners();

    document.querySelectorAll('.tab-link').forEach(button => {
        button.addEventListener('click', (e) => {
            const clickedTab = e.currentTarget;
            const targetTabName = clickedTab.dataset.tab;
            if (!targetTabName) return;
            document.querySelectorAll('.tab-link').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            clickedTab.classList.add('active');
            const targetContent = document.getElementById(targetTabName);
            if(targetContent) { targetContent.classList.add('active'); }
        });
    });

    displayFilterInput.addEventListener('keyup', () => {
        clearTimeout(filterTimeout);
        filterTimeout = setTimeout(applyDisplayFilter, 300);
    });

    function applyDisplayFilter() {
        const textFilter = displayFilterInput.value.toLowerCase();
        const rows = packetTableBody.querySelectorAll('tr');
        rows.forEach(row => {
            const cells = row.cells;
            const rowData = (cells[1].textContent + cells[2].textContent + cells[3].textContent + cells[4].textContent + cells[6].textContent).toLowerCase();
            if (rowData.includes(textFilter)) {
                row.classList.remove('hidden-row');
            } else {
                row.classList.add('hidden-row');
            }
        });
    }

    selectTrigger.addEventListener('click', (e) => {
        e.stopPropagation();
        if (isSniffing) return;
        selectItemsContainer.classList.toggle('select-hide');
        selectTrigger.classList.toggle('select-arrow-active');
    });

    window.addEventListener('click', () => {
        if (!selectItemsContainer.classList.contains('select-hide')) {
            selectItemsContainer.classList.add('select-hide');
            selectTrigger.classList.remove('select-arrow-active');
        }
    });

    editNameBtn.addEventListener('click', () => {
        sessionNameDisplay.classList.add('hidden');
        sessionNameInput.classList.remove('hidden');
        editNameBtn.classList.add('hidden');
        saveNameBtn.classList.remove('hidden');
        sessionNameInput.value = sessionNameDisplay.textContent;
        sessionNameInput.focus();
    });

    saveNameBtn.addEventListener('click', () => {
        sessionNameDisplay.textContent = sessionNameInput.value.trim() || "Untitled Session";
        sessionNameDisplay.classList.remove('hidden');
        sessionNameInput.classList.add('hidden');
        editNameBtn.classList.remove('hidden');
        saveNameBtn.classList.add('hidden');
    });

    function loginSuccess() {
        welcomeScreen.style.opacity = '0';
        setTimeout(() => {
            welcomeScreen.style.display = 'none';
            splashScreen.style.display = 'flex';
            setTimeout(showDashboard, 4500);
        }, 500);
    }

    function showDashboard() {
        splashScreen.style.opacity = '0';
        setTimeout(() => {
            splashScreen.style.display = 'none';
            mainDashboard.style.display = 'grid';
        }, 1500);
    }

    // --- NEW: Infinite scroll event listener ---
    tableContainer.addEventListener('scroll', () => {
        // If user is near the bottom of the scroll, load more
        const threshold = 200; // pixels from bottom
        if (tableContainer.scrollTop + tableContainer.clientHeight >= tableContainer.scrollHeight - threshold) {
            loadMorePackets();
        }
    });

    if (typeof window.eel !== 'undefined') {
        eel.expose(add_packets_to_ui);
        eel.expose(update_sniff_status);
        eel.expose(show_error);
    }

    function add_packets_to_ui(packets) {
        try {
            const tableFragment = document.createDocumentFragment();
            const credsFragment = document.createDocumentFragment();
            let foundCredsInBatch = false;

            for (const packet of packets) {
                // Don't add if already exists (handles potential race conditions)
                if (document.querySelector(`tr[data-id="${packet.id}"]`)) continue;

                allPacketIds.push(packet.id);
                const row = createPacketRow(packet); // Use a helper function

                if (packet.sensitive_data && packet.sensitive_data.length > 0) {
                    row.classList.add('cred-row');
                    foundCredsInBatch = true;
                    packet.sensitive_data.forEach(cred => {
                        credCount++;
                        credsFragment.appendChild(createCredentialCard(cred, packet));
                    });
                }
                tableFragment.appendChild(row);
                packetCount++;
            }

            if (packetTableBody.querySelector('.empty-state-cell')) {
                packetTableBody.innerHTML = '';
            }

            // *** MODIFIED: Prepend new packets to the top of the table ***
            packetTableBody.prepend(tableFragment);

            if (credentialsContainer.querySelector('.empty-state-text')) {
                credentialsContainer.innerHTML = '';
            }
            credentialsContainer.prepend(credsFragment);

            packetCountEl.innerText = packetCount;
            if (foundCredsInBatch) {
                updateCredBadge();
                triggerCredentialAlarm();
            }
            updateStatsDisplay();
        } catch (error) {
            console.error("Error processing packet batch:", error);
        }
    }

    // --- NEW: Function to load older packets from the DB ---
    async function loadMorePackets() {
        if (isLoadingMore || !isSniffing || noMorePacketsToLoad) {
            return;
        }
        isLoadingMore = true;

        try {
            const olderPackets = await eel.get_packets_page(currentOffset, PACKET_PAGE_SIZE)();
            if (olderPackets && olderPackets.length > 0) {
                const tableFragment = document.createDocumentFragment();
                for (const packet of olderPackets) {
                    // Don't add if it somehow already exists
                    if (document.querySelector(`tr[data-id="${packet.id}"]`)) continue;
                    tableFragment.appendChild(createPacketRow(packet));
                }
                // *** Append older packets to the bottom ***
                packetTableBody.appendChild(tableFragment);
                currentOffset += olderPackets.length;
            } else {
                noMorePacketsToLoad = true; // No more data to fetch
            }
        } catch (error) {
            console.error("Failed to load more packets:", error);
        } finally {
            isLoadingMore = false;
        }
    }

    // --- NEW: Helper function to create a table row from a packet object ---
    function createPacketRow(packet) {
        const row = document.createElement('tr');
        row.dataset.id = packet.id;

        const protoLower = (packet.proto || '').toLowerCase();
        if (protoLower.startsWith('http')) row.classList.add('proto-http');
        else if (protoLower.startsWith('https')) row.classList.add('proto-https');
        else if (protoLower.startsWith('dns')) row.classList.add('proto-dns');
        else if (protoLower.startsWith('ftp')) row.classList.add('proto-ftp');
        else if (protoLower.startsWith('tcp')) row.classList.add('proto-tcp');
        else if (protoLower.startsWith('udp')) row.classList.add('proto-udp');
        else if (protoLower.startsWith('arp')) row.classList.add('proto-arp');

        const rowContent = `<td>${packet.time}</td><td>${packet.src_full || packet.src || 'N/A'}</td><td>${packet.dst_full || packet.dst || 'N/A'}</td><td>${packet.proto}</td><td>${packet.domain}</td><td>${packet.size}</td><td>${packet.info}</td>`;
        row.innerHTML = rowContent;
        row.addEventListener('click', () => showPacketDetails(packet.id));
        row.style.cursor = 'pointer';

        // Apply display filter to the new row
        const textFilter = displayFilterInput.value.toLowerCase();
        const rowData = (packet.src_full + packet.dst_full + packet.proto + packet.domain + packet.info).toLowerCase();
        if (textFilter && !rowData.includes(textFilter)) {
            row.classList.add('hidden-row');
        }

        // Update stats
        protoStats[packet.proto] = (protoStats[packet.proto] || 0) + 1;
        if (packet.src_port) { portStats[packet.src_port] = (portStats[packet.src_port] || 0) + 1; }
        if (packet.dst_port) { portStats[packet.dst_port] = (portStats[packet.dst_port] || 0) + 1; }

        return row;
    }


    function update_sniff_status(sniffing_status) {
        isSniffing = sniffing_status;
        const buttonText = toggleSniffBtn.querySelector('.text');
        const buttonIcon = toggleSniffBtn.querySelector('.icon');
        if (sniffing_status) {
            toggleSniffBtn.classList.remove('start-mode');
            toggleSniffBtn.classList.add('stop-mode');
            buttonText.textContent = 'Stop Sniffing';
            buttonIcon.textContent = '■';
            statusText.innerText = `Status: Sniffing...`;
            statusIndicator.className = 'status-indicator-on';
            mainContent.classList.add('is-sniffing');
        } else {
            toggleSniffBtn.classList.remove('stop-mode');
            toggleSniffBtn.classList.add('start-mode');
            buttonText.textContent = 'Start Sniffing';
            buttonIcon.textContent = '▶';
            statusText.innerText = 'Status: Stopped';
            statusIndicator.className = 'status-indicator-off';
            mainContent.classList.remove('is-sniffing');
        }
    }

    function show_error(message) {
        console.error('Backend error:', message);
        statusText.innerText = `Error: ${message}`;
        statusText.style.color = 'var(--accent-red)';
        setTimeout(() => { statusText.style.color = ''; if(!isSniffing) statusText.innerText = 'Status: Ready'; }, 5000);
    }

    toggleSniffBtn.addEventListener('click', async () => {
        if (isSniffing) {
            try { await eel.stop_sniffing()(); } catch (error) { show_error('Failed to stop sniffing'); }
        } else {
            if (!selectedInterfaceGuid) {
                alert('Please select a network interface first.');
                return;
            }
            const finalFilter = bpfFilter.value.trim();
            try {
                await clearAllData(); // Clear data from previous session
                await eel.start_sniffing(selectedInterfaceGuid, finalFilter)();
            } catch (error) { show_error('Failed to start sniffing. Run as administrator.'); }
        }
    });

    async function loadInterfaces() {
        try {
            interfaces = await eel.get_interfaces()();
            selectItemsContainer.innerHTML = '';
            if (Object.keys(interfaces).length === 0) {
                selectTrigger.innerHTML = '<span>No interfaces found. Run as admin.</span>';
                return;
            }

            for (const guid in interfaces) {
                const iface = interfaces[guid];
                const item = document.createElement('div');
                item.className = 'select-item';
                item.dataset.value = guid;
                item.innerHTML = `<div><span class="iface-status-dot ${iface.status === 'up' ? 'status-up' : 'status-down'}"></span><strong class="iface-name">${iface.name}</strong></div><div class="iface-ip">${iface.ip}</div>`;
                item.addEventListener('click', function(e) {
                    e.stopPropagation();
                    selectTrigger.innerHTML = `<div>${this.innerHTML}</div>`;
                    selectedInterfaceGuid = this.dataset.value;
                    selectItemsContainer.classList.add('select-hide');
                    selectTrigger.classList.remove('select-arrow-active');
                });
                selectItemsContainer.appendChild(item);
            }
        } catch (error) {
            show_error("Could not load network interfaces.");
        }
    }

    if (saveAllPcapBtn) {
        saveAllPcapBtn.addEventListener('click', async () => {
            toggleButtonLoading(saveAllPcapBtn, true);
            try {
                const fileTypes = [['PCAP file', '*.pcap']];
                const path = await eel.show_save_dialog(fileTypes)();
                if (path) { const result = await eel.export_pcap(path, allPacketIds)(); statusText.innerText = result.message; }
            } catch (error) { show_error('Failed to save PCAP file'); }
            toggleButtonLoading(saveAllPcapBtn, false);
        });
    }

    if (exportCredsTxtBtn) {
        exportCredsTxtBtn.addEventListener('click', async () => {
            toggleButtonLoading(exportCredsTxtBtn, true);
            try {
                let content = "adcAM Sniffer - Detected Credentials Report\n=========================================\n\n";
                document.querySelectorAll('.credential-card').forEach(card => {
                    const type = card.querySelector('.credential-card-header span:last-child').innerText;
                    const value = card.querySelector('.credential-card-body .value').innerText;
                    const footer = card.querySelector('.credential-card-footer').innerText;
                    content += `Type: ${type}\nValue: ${value}\nContext: ${footer}\n----------------------------------\n`;
                });
                const fileTypes = [['Text file', '*.txt']];
                const path = await eel.show_save_dialog(fileTypes)();
                if (path) { const result = await eel.export_txt(path, content)(); statusText.innerText = result.message; }
            } catch (error) { show_error('Failed to export credentials'); }
            toggleButtonLoading(exportCredsTxtBtn, false);
        });
    }

    async function clearAllData() {
        if(isSniffing) await eel.stop_sniffing()(); // Stop first if running

        // *** MODIFIED: Call backend to clear DB ***
        await eel.clear_packets_db()();

        packetTableBody.innerHTML = '<tr><td colspan="7" class="empty-state-cell">Start sniffing to see live packets...</td></tr>';
        credentialsContainer.innerHTML = '<p class="empty-state-text">No credentials captured yet.</p>';
        packetCount = 0; credCount = 0; allPacketIds = [];
        protoStats = {}; portStats = {};
        packetCountEl.innerText = '0';
        updateCredBadge();
        updateStatsDisplay();
        displayFilterInput.value = '';

        // Reset infinite scroll state
        currentOffset = 0;
        noMorePacketsToLoad = false;
        isLoadingMore = false;

        // Don't clear BPF filter or session name
    }

    function createCredentialCard(cred, packet) {
        const card = document.createElement('div');
        card.className = 'credential-card';
        const icons = {"Password": "🔒", "Username": "👤", "Email": "✉️", "Token/Key": "🗝️"};
        card.innerHTML = `<div class="credential-card-header"><span class="icon">${icons[cred.type] || '❓'}</span><span>${cred.type} Found</span></div><div class="credential-card-body"><div class="label">Value:</div><div class="value">${escapeHtml(cred.value)}</div></div><div class="credential-card-footer">From ${packet.src} to ${packet.dst}</div>`;
        return card;
    }

    function triggerCredentialAlarm() {
        credentialsTabBtn.classList.add('alarm');
        setTimeout(() => { credentialsTabBtn.classList.remove('alarm'); }, 2400);
    }

    async function showPacketDetails(packetId) {
        packetDetailContent.innerHTML = '<p style="text-align: center; padding: 40px;">Loading details...</p>';
        packetDetailModal.style.display = 'flex';
        try {
            const packet = await eel.get_packet_details(packetId)();
            if (!packet) {
                packetDetailContent.innerHTML = '<p style="text-align: center; padding: 40px; color: var(--accent-red);">Error: Could not retrieve packet details.</p>';
                return;
            }
            let content = `<div class="modal-tabs"><button class="modal-tab-link active" data-tab="summary">Summary</button><button class="modal-tab-link" data-tab="details">Layer Details</button><button class="modal-tab-link" data-tab="payload">Raw Payload</button></div><div id="summary" class="modal-tab-content active"><div class="detail-grid"><div class="detail-section"><h4>- General</h4><div class="detail-row"><span class="detail-label">Timestamp:</span> <span class="detail-value">${packet.time}</span></div><div class="detail-row"><span class="detail-label">Size:</span> <span class="detail-value">${packet.size} bytes</span></div><div class="detail-row"><span class="detail-label">Protocol:</span> <span class="detail-value">${packet.proto}</span></div></div><div class="detail-section"><h4>- Network</h4><div class="detail-row"><span class="detail-label">Source:</span> <span class="detail-value">${packet.src_full || packet.src}</span></div><div class="detail-row"><span class="detail-label">Destination:</span> <span class="detail-value">${packet.dst_full || packet.dst}</span></div>${packet.domain && packet.domain !== 'N/A' ? `<div class="detail-row"><span class="detail-label">Domain/Sub:</span> <span class="detail-value">${packet.domain}</span></div>` : ''}</div></div></div><div id="details" class="modal-tab-content"><div class="detail-grid">${packet.ip_ttl ? `<div class="detail-section"><h4>- IP Layer</h4><div class="detail-row"><span class="detail-label">Time to Live (TTL):</span> <span class="detail-value">${packet.ip_ttl}</span></div><div class="detail-row"><span class="detail-label">Flags:</span> <span class="detail-value">${packet.ip_flags}</span></div></div>` : ''}${packet.tcp_flags ? `<div class="detail-section"><h4>- TCP Layer</h4><div class="detail-row"><span class="detail-label">Flags:</span> <span class="detail-value">${packet.tcp_flags}</span></div><div class="detail-row"><span class="detail-label">Sequence:</span> <span class="detail-value">${packet.tcp_seq}</span></div><div class="detail-row"><span class="detail-label">Acknowledgment:</span> <span class="detail-value">${packet.tcp_ack}</span></div><div class="detail-row"><span class="detail-label">Window Size:</span> <span class="detail-value">${packet.tcp_window}</span></div></div>` : ''}</div><div class="port-note"><strong>Note:</strong> This tool is a passive sniffer and cannot scan for all open ports. It only shows the source and destination ports used in this specific communication.</div></div><div id="payload" class="modal-tab-content" style="flex-grow: 1;"><div class="hexdump-container">${formatHexdump(packet.raw_hex)}</div></div>`;
            packetDetailContent.innerHTML = content;

            const saveBtn = document.getElementById('save-single-pcap-btn');
            saveBtn.onclick = async () => {
                toggleButtonLoading(saveBtn, true);
                const fileTypes = [['PCAP file', '*.pcap']];
                const path = await eel.show_save_dialog(fileTypes)();
                if (path) {
                    const result = await eel.export_single_pcap(path, packetId)();
                    statusText.innerText = result.message;
                }
                toggleButtonLoading(saveBtn, false);
            };

            packetDetailContent.querySelectorAll('.modal-tab-link').forEach(button => {
                button.addEventListener('click', (e) => {
                    packetDetailContent.querySelectorAll('.modal-tab-link').forEach(btn => btn.classList.remove('active'));
                    packetDetailContent.querySelectorAll('.modal-tab-content').forEach(c => c.classList.remove('active'));
                    const tabButton = e.currentTarget;
                    tabButton.classList.add('active');
                    packetDetailContent.querySelector(`#${tabButton.dataset.tab}`).classList.add('active');
                });
            });
        } catch(error) {
            console.error("Failed to get packet details:", error);
            packetDetailContent.innerHTML = '<p style="text-align: center; padding: 40px; color: var(--accent-red);">Error: Could not retrieve packet details.</p>';
        }
    }

    function updateStatsDisplay() {
        statPacketCount.textContent = packetCount;
        statCredCount.textContent = credCount;
        const sortedProtocols = Object.entries(protoStats).sort(([,a],[,b]) => b-a).slice(0, 10);
        topProtocolsList.innerHTML = '';
        if (sortedProtocols.length === 0) {
            topProtocolsList.innerHTML = '<li class="empty-state-text" style="padding:0;">No protocols yet.</li>';
        } else {
            for (const [proto, count] of sortedProtocols) {
                topProtocolsList.innerHTML += `<li><span>${proto}</span><strong>${count}</strong></li>`;
            }
        }

        const sortedPorts = Object.entries(portStats).sort(([,a],[,b]) => b-a).slice(0, 10);
        topPortsList.innerHTML = '';
        if (sortedPorts.length === 0) {
            topPortsList.innerHTML = '<li class="empty-state-text" style="padding:0;">No ports detected yet.</li>';
        } else {
            for (const [port, count] of sortedPorts) {
                topPortsList.innerHTML += `<li><span>Port ${port}</span><strong>${count}</strong></li>`;
            }
        }
    }

    function formatHexdump(hexString) {
        if (!hexString) return 'No payload data.';
        let result = '';
        const bytes = hexString.match(/.{1,2}/g) || [];
        for (let i = 0; i < bytes.length; i += 16) {
            const chunk = bytes.slice(i, i + 16);
            const address = i.toString(16).padStart(8, '0');
            const hexPart = chunk.map(b => b.padStart(2, '0')).join(' ');
            const asciiPart = chunk.map(b => { const charCode = parseInt(b, 16); return (charCode >= 32 && charCode <= 126) ? String.fromCharCode(charCode) : '.'; }).join('');
            result += `${address}  <span class="hexdump-hex">${hexPart.padEnd(47)}</span> <span class="hexdump-ascii">${asciiPart}</span>\n`;
        }
        return result;
    }

    function updateCredBadge() {
        credCountBadge.innerText = credCount;
        credCountBadge.style.display = credCount > 0 ? 'inline-block' : 'none';
    }

    function escapeHtml(unsafe) {
        return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    }

    function toggleButtonLoading(btn, isLoading) {
        if (isLoading) { btn.disabled = true; btn.classList.add('loading'); } else { btn.disabled = false; btn.classList.remove('loading'); }
    }

    // Set initial empty states
    packetTableBody.innerHTML = '<tr><td colspan="7" class="empty-state-cell">Select an interface and start sniffing...</td></tr>';
    credentialsContainer.innerHTML = '<p class="empty-state-text">No credentials captured yet.</p>';
    updateStatsDisplay();

    setTimeout(() => { loadInterfaces(); }, 100);
});