/* ========================================
   Config Tab - Settings with Collapsible Sections
   ======================================== */
'use strict';

const ConfigTab = {
    config: null,

    init() {
        const panel = document.getElementById('tab-config');
        panel.innerHTML = `
            <div class="config-panel">
                <div class="config-header">
                    <button class="btn btn-gold" id="cfg-save">Save Config</button>
                    <button class="btn" id="cfg-restore">Restore Defaults</button>
                </div>
                <div class="config-body" id="config-body">
                    <div class="empty-state">Loading configuration...</div>
                </div>
                <div style="margin-top:24px;border-top:1px solid var(--border);padding-top:16px">
                    <span class="section-title" style="margin:0">Reset</span>
                    <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">
                        <button class="btn btn-danger" id="cfg-clear-hosts">CLEAR HOSTS LIST</button>
                        <button class="btn btn-danger" id="cfg-clear-scan-logs">CLEAR SCAN LOGS</button>
                        <button class="btn btn-danger" id="cfg-clear-stats">CLEAR STATS</button>
                        <button class="btn btn-danger" id="cfg-clear-stolen">CLEAR STOLEN FILES</button>
                        <button class="btn btn-danger" id="cfg-clear-creds">CLEAR CREDENTIALS</button>
                        <button class="btn btn-danger" id="cfg-clear-all" style="background:#7a1f1f">CLEAR ALL</button>
                    </div>
                </div>
            </div>
        `;

        document.getElementById('cfg-save').addEventListener('click', () => this.save());
        document.getElementById('cfg-restore').addEventListener('click', () => this.restore());
        document.getElementById('cfg-clear-hosts').addEventListener('click', () => this._clear('/clear_hosts', 'CLEAR HOSTS LIST'));
        document.getElementById('cfg-clear-scan-logs').addEventListener('click', () => this._clear('/clear_scan_logs', 'CLEAR SCAN LOGS'));
        document.getElementById('cfg-clear-stats').addEventListener('click', () => this._clear('/clear_stats', 'CLEAR STATS'));
        document.getElementById('cfg-clear-stolen').addEventListener('click', () => this._clear('/clear_stolen_files', 'CLEAR STOLEN FILES'));
        document.getElementById('cfg-clear-creds').addEventListener('click', () => this._clear('/clear_credentials', 'CLEAR CREDENTIALS'));
        document.getElementById('cfg-clear-all').addEventListener('click', () => this._clear('/clear_all', 'CLEAR ALL'));
    },

    async _clear(endpoint, label) {
        if (!confirm(label + ' — proceed?')) return;
        try {
            await App.post(endpoint);
            App.toast(label + ' done', 'success');
        } catch (e) {
            App.toast(label + ' failed: ' + e, 'error');
        }
    },

    activate() {
        this.loadConfig();
    },

    deactivate() {},

    async loadConfig() {
        try {
            // Fetch available themes so the `theme` config field renders as a dropdown.
            try {
                var themes = await App.api('/api/themes');
                if (themes && themes.themes && themes.themes.length) {
                    this.enumOptions['theme'] = themes.themes.map(function(t) {
                        return { value: t.id, label: t.name };
                    });
                }
            } catch (e) { /* fall through, theme will stay text */ }

            this.config = await App.api('/load_config');
            this.render();
        } catch (e) {
            document.getElementById('config-body').innerHTML = '<div class="empty-state">Error loading config.</div>';
        }
    },

    render() {
        if (!this.config) return;
        const body = document.getElementById('config-body');

        // Group keys by section titles (__title_*)
        const sections = [];
        var currentSection = { title: 'General', keys: [] };
        sections.push(currentSection);

        const keys = Object.keys(this.config);
        keys.forEach(key => {
            if (key.startsWith('__title_')) {
                currentSection = { title: this.config[key], keys: [] };
                sections.push(currentSection);
            } else if (!key.startsWith('__')) {
                currentSection.keys.push(key);
            }
        });

        body.innerHTML = sections.filter(s => s.keys.length).map((section, idx) => {
            const fields = section.keys.map(key => this.renderField(key, this.config[key])).join('');
            var expandedClass = idx === 0 ? ' expanded' : '';
            return '<div class="config-section' + expandedClass + '" id="cfg-section-' + idx + '">' +
                '<div class="config-section-header" onclick="ConfigTab.toggleSection(' + idx + ')">' +
                '<span>' + section.title + '</span>' +
                '<span class="collapse-icon">&#9654;</span>' +
                '</div>' +
                '<div class="config-section-body"><div class="config-grid">' + fields + '</div></div>' +
                '</div>';
        }).join('');
    },

    enumOptions: {
        'attack_order': [
            { value: 'spread', label: 'Spread (default) - All hosts, then vuln scans' },
            { value: 'per_host', label: 'Per Host - Complete each host before moving on' },
            { value: 'per_phase', label: 'Per Phase - Each attack phase across all hosts' }
        ],
        'screen_rotation': [
            { value: '0', label: 'Portrait (0°)' },
            { value: '90', label: 'Landscape (90°)' },
            { value: '180', label: 'Portrait inverted (180°)' },
            { value: '270', label: 'Landscape (270° - default)' }
        ],
        'vuln_scan_mode': [
            { value: 'lightweight', label: 'Lightweight (vuln category — fast)' },
            { value: 'full', label: 'Full (vuln + exploit + auth + default — slower, more findings)' }
        ],
        'dictionary_mode': [
            { value: 'default', label: 'Default (11 users × 20 passwords ≈ 220 combos — fast)' },
            { value: 'aggressive', label: 'Aggressive (102 users × 106 passwords ≈ 10,800 combos)' },
            { value: 'custom', label: 'Custom (specify files below)' }
        ]
    },

    displayNames: {
        // Storage
        'data_dir': 'Data Directory (blank = ~/.loki/data; restart required to apply)',
        // Vulnerability Scan
        'vuln_scan_mode': 'NSE Scan Depth',
        'enable_nuclei': 'Enable Nuclei (templated vuln scanner)',
        'nuclei_severity': 'Nuclei: severity filter (info,low,medium,high,critical)',
        'nuclei_rate_limit': 'Nuclei: max requests per second',
        'nuclei_templates_dir': 'Nuclei: templates directory (blank = use defaults)',
        // Brute Force Dictionary
        'dictionary_mode': 'Wordlist',
        'dictionary_users_custom': 'Custom Users File (path or filename in resources/dictionary/)',
        'dictionary_passwords_custom': 'Custom Passwords File (path or filename in resources/dictionary/)',
        // Attack Settings
        'manual_mode': 'Start in Manual Mode',
        'clear_hosts_on_startup': 'Clear All Hosts on Startup',
        'attack_order': 'Attack Order Strategy',
        'brute_force_running': 'Enable Brute Force Attacks',
        'file_steal_running': 'Enable File Stealing',
        'scan_vuln_running': 'Enable Vulnerability Scans',

        // Retry Settings
        'retry_success_actions': 'Re-run Successful Attacks',
        'retry_failed_actions': 'Retry Failed Attacks',
        'failed_retry_delay': 'Wait Before Retrying Failed (seconds)',
        'success_retry_delay': 'Wait Before Re-running Success (seconds)',

        // Network & Scanning
        'scan_interval': 'Time Between Network Scans (seconds)',
        'scan_network_prefix': 'Subnet Size (CIDR prefix, e.g. 24 = /24)',
        'nmap_scan_aggressivity': 'Nmap Scan Speed (-T0 slowest to -T5 fastest)',
        'vuln_scan_timeout': 'Vuln Scan Timeout per Batch (seconds)',
        'portstart': 'Port Range Start',
        'portend': 'Port Range End',
        'portlist': 'Additional Ports to Scan (supports ranges like 1-1024)',
        'blacklistcheck': 'Enable Host Blacklisting',
        'blacklist_gateway': 'Automatically Blacklist Gateway',
        'mac_scan_blacklist': 'Blacklisted MAC Addresses',
        'ip_scan_blacklist': 'Blacklisted IP Addresses',

        // File Stealing
        'steal_file_names': 'Target File Names',
        'steal_file_extensions': 'Target File Extensions',
        'steal_max_depth': 'Max Folder Depth to Search',
        'steal_max_files': 'Max Files to Download per Share',

        // Delay Settings
        'startup_delay': 'Startup Delay (seconds)',
        'web_delay': 'Web UI Auto-Refresh Interval (seconds)',
        'comment_delaymin': 'LCD Comment Minimum Delay (seconds)',
        'comment_delaymax': 'LCD Comment Maximum Delay (seconds)',
        'image_display_delaymin': 'LCD Image Minimum Display Time (seconds)',
        'image_display_delaymax': 'LCD Image Maximum Display Time (seconds)',
        'timewait_smb': 'Delay Between SMB Attempts (seconds)',
        'timewait_ssh': 'Delay Between SSH Attempts (seconds)',
        'timewait_telnet': 'Delay Between Telnet Attempts (seconds)',
        'timewait_ftp': 'Delay Between FTP Attempts (seconds)',
        'timewait_sql': 'Delay Between SQL Attempts (seconds)',
        'timewait_rdp': 'Delay Between RDP Attempts (seconds)',

        // Performance
        'worker_threads': 'Concurrent Brute Force Threads',
        'max_failed_retries': 'Max Retries Before Giving Up',
        'bruteforce_attempt_timeout': 'Brute Force Per-Attempt Timeout (seconds)',
        'bruteforce_max_retries': 'Brute Force Max Retries per Credential',
        'bruteforce_max_total_retries': 'Brute Force Max Total Retries Before Abort',
        'displaying_csv': 'Save Detailed Scan Results to CSV',

        // Logging
        'log_debug': 'Show Debug Messages',
        'log_info': 'Show Info Messages',
        'log_warning': 'Show Warning Messages',
        'log_error': 'Show Error Messages',
        'log_critical': 'Show Critical Messages',

        // Display
        'screen_brightness': 'Screen Brightness (0-100)',
        'screen_dim_brightness': 'Dimmed Brightness (0-100)',
        'screen_dim_timeout': 'Dim Screen After Inactivity (seconds)',

        // Theme
        'os_detection': 'Enable OS Fingerprinting (nmap -O)',
        'enable_vulners_lookup': 'Enable Vulners.com CVE Lookup (auto-detects internet)',
        'scan_enumeration': 'Enable Service Enumeration (SMB shares, SSH algos, etc.)',

        'override_theme_delays': 'Override Theme Animation Delays',
        'override_theme_comment_delays': 'Override Theme Comment Delays'
    },

    getDisplayName(key) {
        return this.displayNames[key] || key;
    },

    renderField(key, value) {
        var id = 'cfg-' + key;
        var label = this.getDisplayName(key);

        // Enum fields render as dropdown selects (full width to avoid uneven grid)
        if (this.enumOptions[key]) {
            var options = this.enumOptions[key].map(function(opt) {
                return '<option value="' + opt.value + '"' +
                    (String(value) === opt.value ? ' selected' : '') + '>' +
                    opt.label + '</option>';
            }).join('');
            return '<div class="form-group form-group-full">' +
                '<label class="form-label" for="' + id + '">' + label + '</label>' +
                '<select class="form-input" id="' + id + '" data-key="' + key + '" data-type="string">' +
                options + '</select></div>';
        }

        if (typeof value === 'boolean') {
            return '<div class="form-group">' +
                '<label class="toggle-wrap">' +
                '<div class="toggle">' +
                '<input type="checkbox" id="' + id + '" data-key="' + key + '" ' + (value ? 'checked' : '') + '>' +
                '<span class="toggle-slider"></span>' +
                '</div>' +
                '<span>' + label + '</span>' +
                '</label></div>';
        }

        if (Array.isArray(value)) {
            return '<div class="form-group">' +
                '<label class="form-label" for="' + id + '">' + label + '</label>' +
                '<input class="form-input" id="' + id + '" data-key="' + key + '" data-type="array" ' +
                'value="' + value.join(', ') + '" placeholder="comma-separated values">' +
                '</div>';
        }

        if (typeof value === 'number') {
            var isFloat = !Number.isInteger(value);
            return '<div class="form-group">' +
                '<label class="form-label" for="' + id + '">' + label + '</label>' +
                '<input class="form-input" type="number" id="' + id + '" data-key="' + key + '" data-type="number" ' +
                'value="' + value + '" step="' + (isFloat ? '0.1' : '1') + '">' +
                '</div>';
        }

        // String
        return '<div class="form-group">' +
            '<label class="form-label" for="' + id + '">' + label + '</label>' +
            '<input class="form-input" type="text" id="' + id + '" data-key="' + key + '" data-type="string" ' +
            'value="' + String(value).replace(/"/g, '&quot;') + '">' +
            '</div>';
    },

    toggleSection(idx) {
        var el = document.getElementById('cfg-section-' + idx);
        if (el) el.classList.toggle('expanded');
    },

    async save() {
        var data = {};
        document.querySelectorAll('#config-body [data-key]').forEach(el => {
            var key = el.dataset.key;
            var type = el.dataset.type;

            if (el.type === 'checkbox') {
                data[key] = el.checked;
            } else if (type === 'array') {
                data[key] = el.value.split(',').map(s => s.trim()).filter(s => s);
            } else if (type === 'number') {
                var v = el.value;
                data[key] = v.includes('.') ? parseFloat(v) : parseInt(v, 10);
            } else {
                var v = el.value;
                if (v.match(/^\d+$/)) data[key] = parseInt(v, 10);
                else if (v.match(/^\d+\.\d+$/)) data[key] = parseFloat(v);
                else data[key] = v;
            }
        });

        try {
            await App.post('/save_config', data);
            App.toast('Configuration saved', 'success');
        } catch (e) {
            App.toast('Save failed: ' + e.message, 'error');
        }
    },

    async restore() {
        if (!await App.confirm('Restore all settings to defaults?')) return;
        try {
            this.config = await App.api('/restore_default_config');
            this.render();
            App.toast('Defaults restored', 'success');
        } catch (e) {
            App.toast('Failed: ' + e.message, 'error');
        }
    }
};

App.registerTab('config', ConfigTab);
