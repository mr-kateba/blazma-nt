import { parseCoded } from '@shared/errors'
import type { Language } from '@shared/types'

/**
 * Translation table. Keys are grouped by area; every key must exist in both
 * languages, which the TranslationKey type enforces at compile time.
 */
const en = {
  'app.name': 'blazma.nt',
  'app.tagline': 'Network monitoring & traffic analysis',

  'nav.dashboard': 'Dashboard',
  'nav.devices': 'Devices',
  'nav.live': 'Live Traffic',
  'nav.connections': 'Connections',
  'nav.protocols': 'Protocols',
  'nav.dns': 'DNS',
  'nav.unencrypted': 'Unencrypted',
  'nav.tls': 'HTTPS / TLS',
  'nav.alerts': 'Alerts',
  'nav.analytics': 'Analytics',
  'nav.pcap': 'Packet Capture',
  'nav.logs': 'Logs',
  'nav.settings': 'Settings',

  'engine.start': 'Start monitoring',
  'engine.stop': 'Stop monitoring',
  'engine.running': 'Monitoring',
  'engine.stopped': 'Stopped',
  'engine.starting': 'Starting…',
  'engine.stopping': 'Stopping…',
  'engine.error': 'Error',
  'engine.selectInterface': 'Select an interface',
  'engine.noInterface': 'Choose a network interface to begin.',
  'engine.privacyOn': 'Privacy Mode is on',

  'stat.devices': 'Devices',
  'stat.online': 'Online',
  'stat.traffic': 'Traffic',
  'stat.upload': 'Upload',
  'stat.download': 'Download',
  'stat.connections': 'Active connections',
  'stat.packetsPerSec': 'Packets/sec',
  'stat.bytesPerSec': 'Throughput',

  'chart.trafficOverTime': 'Traffic over time',
  'chart.uploadVsDownload': 'Upload vs Download',
  'chart.packetsPerSecond': 'Packets per second',
  'chart.perDevice': 'Traffic per device',
  'chart.perProtocol': 'Traffic per protocol',

  'panel.topDevices': 'Top devices',
  'panel.topProtocols': 'Top protocols',
  'panel.topDestinations': 'Top destinations',
  'panel.recentAlerts': 'Recent alerts',
  'panel.recentConnections': 'Recent connections',

  'col.device': 'Device',
  'col.name': 'Name',
  'col.ipv4': 'IPv4',
  'col.ipv6': 'IPv6',
  'col.mac': 'MAC address',
  'col.vendor': 'Vendor',
  'col.hostname': 'Hostname',
  'col.firstSeen': 'First seen',
  'col.lastSeen': 'Last seen',
  'col.status': 'Status',
  'col.upload': 'Upload',
  'col.download': 'Download',
  'col.connections': 'Connections',
  'col.time': 'Time',
  'col.source': 'Source',
  'col.destination': 'Destination',
  'col.port': 'Port',
  'col.protocol': 'Protocol',
  'col.transport': 'Transport',
  'col.direction': 'Direction',
  'col.size': 'Size',
  'col.encryption': 'Encryption',
  'col.state': 'State',
  'col.duration': 'Duration',
  'col.packets': 'Packets',
  'col.bytes': 'Bytes',
  'col.query': 'Query',
  'col.type': 'Type',
  'col.response': 'Response',
  'col.server': 'Server',
  'col.severity': 'Severity',
  'col.reason': 'Reason',
  'col.metadata': 'Detected metadata',
  'col.sni': 'Server name (SNI)',
  'col.version': 'Version',
  'col.issuer': 'Certificate issuer',
  'col.subject': 'Certificate subject',
  'col.level': 'Level',
  'col.message': 'Message',
  'col.scope': 'Scope',

  'value.online': 'Online',
  'value.offline': 'Offline',
  'value.encrypted': 'Encrypted',
  'value.unencrypted': 'UNENCRYPTED',
  'value.unknown': 'Unknown',
  'value.up': 'Upload',
  'value.down': 'Download',
  'value.local': 'Local',

  'action.search': 'Search',
  'action.refresh': 'Refresh',
  'action.export': 'Export',
  'action.clear': 'Clear',
  'action.close': 'Close',
  'action.save': 'Save',
  'action.back': 'Back',
  'action.acknowledge': 'Acknowledge',
  'action.acknowledgeAll': 'Acknowledge all',
  'action.pauseDevice': 'Pause device monitoring',
  'action.resumeDevice': 'Resume device monitoring',
  'action.ignoreDevice': 'Ignore device',
  'action.unignoreDevice': 'Stop ignoring',
  'action.details': 'Details',
  'action.apply': 'Apply',
  'action.browse': 'Browse…',

  'filter.all': 'All',
  'filter.encrypted': 'Encrypted',
  'filter.unencrypted': 'Unencrypted',
  'filter.upload': 'Upload',
  'filter.download': 'Download',

  'range.1m': 'Last 1 minute',
  'range.5m': 'Last 5 minutes',
  'range.15m': 'Last 15 minutes',
  'range.1h': 'Last 1 hour',
  'range.24h': 'Last 24 hours',
  'range.7d': 'Last 7 days',
  'range.30d': 'Last 30 days',

  'empty.noData': 'No data yet',
  'empty.startMonitoring': 'Start monitoring to collect data.',
  'empty.noResults': 'Nothing matches this filter.',
  'empty.unencrypted': 'No unencrypted traffic has been observed.',
  'empty.alerts': 'No alerts.',

  'unenc.title': 'Unencrypted traffic',
  'unenc.explain':
    'These protocols send their contents in the clear. Only non-sensitive metadata is shown — credentials, cookies, tokens and message bodies are never collected.',
  'unenc.redacted': '[Sensitive data redacted]',

  'tls.title': 'HTTPS / TLS sessions',
  'tls.explain':
    'Encrypted traffic is never decrypted. Only what TLS itself sends in the clear is shown: the server name, the negotiated version, and certificate names when the handshake exposes them.',

  'dns.title': 'DNS monitor',
  'dns.clearHistory': 'Delete DNS history',
  'dns.clearConfirm': 'Delete all stored DNS queries? This cannot be undone.',

  'pcap.title': 'Packet capture',
  'pcap.explain':
    'Packets are only written to disk while a capture you started is running. Nothing is recorded automatically.',
  'pcap.start': 'Start packet capture',
  'pcap.stop': 'Stop packet capture',
  'pcap.duration': 'Maximum duration (seconds)',
  'pcap.maxSize': 'Maximum file size (MB)',
  'pcap.filter': 'Capture filter (BPF)',
  'pcap.output': 'Output file',
  'pcap.running': 'Capturing…',
  'pcap.written': 'Written',

  'settings.interface': 'Network interface',
  'settings.capture': 'Capture',
  'settings.retention': 'Database retention',
  'settings.privacy': 'Privacy',
  'settings.notifications': 'Notifications',
  'settings.theme': 'Theme',
  'settings.language': 'Language',
  'settings.performance': 'Performance',
  'settings.logging': 'Logging',
  'settings.database': 'Database',
  'settings.privacyMode': 'Privacy Mode',
  'settings.privacyModeHelp':
    'Stops recording anything derived from packet payloads: DNS queries, HTTP metadata and TLS server names. Counters, devices and flows keep working.',
  'settings.storeDns': 'Store DNS queries',
  'settings.storeUnencrypted': 'Store unencrypted metadata',
  'settings.notifyMin': 'Minimum severity for notifications',
  'settings.uiRate': 'UI update rate (Hz)',
  'settings.maxLiveFlows': 'Maximum live rows',
  'settings.logLevel': 'Log level',
  'settings.purge': 'Delete stored data',
  'settings.purgeAll': 'Delete everything',
  'settings.purgeConfirm': 'Delete this data permanently?',
  'settings.dbSize': 'Database size',
  'settings.telemetry': 'Telemetry is disabled and cannot be enabled. No data leaves this computer.',

  'env.npcapMissing': 'Npcap is required to monitor network traffic.',
  'env.npcapHelp':
    'Install Npcap from npcap.com and enable "WinPcap API-compatible mode" during setup, then restart blazma.nt.',
  'env.dumpcapMissing': 'dumpcap.exe was not found.',
  'env.dumpcapHelp':
    'blazma.nt captures through dumpcap, the capture helper installed with Wireshark. Install Wireshark and restart the app.',
  'env.notElevated': 'Not running as Administrator.',
  'env.ready': 'Capture environment ready',

  'legal.notice':
    'Monitor only networks you own or are authorised to monitor. blazma.nt is passive and read-only: it never injects, spoofs or redirects traffic.',

  'log.export': 'Export logs',
  'log.clear': 'Clear logs',

  'nav.router': 'Router Control',
  'router.title': 'Router Control',
  'router.subtitle':
    'Control commands sent directly to your own router through its official API — no spoofing, no injection, no network disruption.',
  'router.detected': 'Detected router',
  'router.notDetected': 'No controllable router detected',
  'router.gateway': 'Gateway',
  'router.model': 'Model',
  'router.notControllable':
    'This router was found but blazma.nt has no control integration for it. Monitoring still works.',
  'router.connect': 'Connect',
  'router.disconnect': 'Disconnect',
  'router.forget': 'Forget saved login',
  'router.connected': 'Connected',
  'router.disconnected': 'Not connected',
  'router.connecting': 'Connecting…',
  'router.username': 'Admin username',
  'router.password': 'Admin password',
  'router.usernameHint': 'Usually "admin". This is your router login, entered only into blazma.nt.',
  'router.save': 'Remember this login (encrypted on this PC)',
  'router.credentialNote':
    'Your password is encrypted with the Windows keystore and never leaves this machine. blazma.nt uses it only to log in to your router.',
  'router.devices': 'Devices on the router',
  'router.block': 'Cut internet',
  'router.unblock': 'Restore internet',
  'router.blocked': 'Blocked',
  'router.online': 'Online',
  'router.offline': 'Offline',
  'router.self': 'This PC',
  'router.blockConfirm': 'Cut this device off the network via the router? You can restore it at any time.',
  'router.blockSelfConfirm':
    'This is the computer running blazma.nt. Blocking it will cut YOUR OWN internet and you may lose access to the router. Continue?',
  'router.rebootConfirm': 'Reboot the router now? Everyone on the network will lose connection for about a minute.',
  'router.reboot': 'Reboot router',
  'router.dns': 'Router DNS',
  'router.dnsPrimary': 'Primary DNS',
  'router.dnsSecondary': 'Secondary DNS',
  'router.dnsAuto': 'Automatic (from carrier)',
  'router.dnsApply': 'Apply DNS',
  'router.dnsNote': 'Changing DNS here affects every device that gets its settings from the router.',
  'router.signal': 'Signal',
  'router.network': 'Network',
  'router.operator': 'Operator',
  'router.refresh': 'Refresh',
  'router.noDevices': 'The router reported no devices yet.',
  'router.warnActive':
    'These are active controls. Blocking a device really disconnects it; rebooting drops every connection.',

  // Backend error codes. The engine sends a code plus an English fallback; the
  // UI shows these when it recognises the code.
  'err.E_NPCAP_MISSING':
    'Npcap is required to monitor network traffic. Install Npcap from npcap.com with "WinPcap API-compatible mode" enabled, then restart blazma.nt.',
  'err.E_DUMPCAP_MISSING':
    'dumpcap.exe was not found. Install Wireshark, which provides the capture helper blazma.nt uses on top of Npcap.',
  'err.E_IFACE_NOT_CAPTURABLE':
    'This adapter has no Npcap capture device. Choose an interface marked as capturable.',
  'err.E_IFACE_UNKNOWN': 'The selected interface no longer exists. Refresh the interface list.',
  'err.E_ALREADY_RUNNING': 'Monitoring is already running. Stop it before selecting another interface.',
  'err.E_CAPTURE_FAILED': 'Capture could not be started.',
  'err.E_CAPTURE_ENDED': 'Capture stopped unexpectedly.',
  'err.E_ROUTER_UNSUPPORTED': 'This router is not controllable by blazma.nt.',
  'err.E_ROUTER_LOGIN': 'Router login failed. Check the username and password.',
  'err.E_ROUTER_NOT_CONNECTED': 'Not connected to the router. Connect first.',
  'err.E_ROUTER_ACTION': 'The router rejected the request.'
} as const

export type TranslationKey = keyof typeof en

const ar: Record<TranslationKey, string> = {
  'app.name': 'blazma.nt',
  'app.tagline': 'مراقبة الشبكة وتحليل حركة البيانات',

  'nav.dashboard': 'لوحة المعلومات',
  'nav.devices': 'الأجهزة',
  'nav.live': 'الحركة المباشرة',
  'nav.connections': 'الاتصالات',
  'nav.protocols': 'البروتوكولات',
  'nav.dns': 'DNS',
  'nav.unencrypted': 'حركة غير مشفّرة',
  'nav.tls': 'HTTPS / TLS',
  'nav.alerts': 'التنبيهات',
  'nav.analytics': 'التحليلات',
  'nav.pcap': 'التقاط الحزم',
  'nav.logs': 'السجلات',
  'nav.settings': 'الإعدادات',

  'engine.start': 'بدء المراقبة',
  'engine.stop': 'إيقاف المراقبة',
  'engine.running': 'قيد المراقبة',
  'engine.stopped': 'متوقّف',
  'engine.starting': 'جارٍ البدء…',
  'engine.stopping': 'جارٍ الإيقاف…',
  'engine.error': 'خطأ',
  'engine.selectInterface': 'اختر واجهة شبكة',
  'engine.noInterface': 'اختر واجهة شبكة للبدء.',
  'engine.privacyOn': 'وضع الخصوصية مفعّل',

  'stat.devices': 'الأجهزة',
  'stat.online': 'متصل',
  'stat.traffic': 'إجمالي الحركة',
  'stat.upload': 'الرفع',
  'stat.download': 'التنزيل',
  'stat.connections': 'الاتصالات النشطة',
  'stat.packetsPerSec': 'حزمة/ثانية',
  'stat.bytesPerSec': 'معدّل النقل',

  'chart.trafficOverTime': 'الحركة عبر الزمن',
  'chart.uploadVsDownload': 'الرفع مقابل التنزيل',
  'chart.packetsPerSecond': 'الحزم في الثانية',
  'chart.perDevice': 'الحركة حسب الجهاز',
  'chart.perProtocol': 'الحركة حسب البروتوكول',

  'panel.topDevices': 'أكثر الأجهزة نشاطًا',
  'panel.topProtocols': 'أكثر البروتوكولات',
  'panel.topDestinations': 'أكثر الوجهات',
  'panel.recentAlerts': 'أحدث التنبيهات',
  'panel.recentConnections': 'أحدث الاتصالات',

  'col.device': 'الجهاز',
  'col.name': 'الاسم',
  'col.ipv4': 'IPv4',
  'col.ipv6': 'IPv6',
  'col.mac': 'عنوان MAC',
  'col.vendor': 'المصنّع',
  'col.hostname': 'اسم المضيف',
  'col.firstSeen': 'أول ظهور',
  'col.lastSeen': 'آخر ظهور',
  'col.status': 'الحالة',
  'col.upload': 'الرفع',
  'col.download': 'التنزيل',
  'col.connections': 'الاتصالات',
  'col.time': 'الوقت',
  'col.source': 'المصدر',
  'col.destination': 'الوجهة',
  'col.port': 'المنفذ',
  'col.protocol': 'البروتوكول',
  'col.transport': 'النقل',
  'col.direction': 'الاتجاه',
  'col.size': 'الحجم',
  'col.encryption': 'التشفير',
  'col.state': 'الحالة',
  'col.duration': 'المدة',
  'col.packets': 'الحزم',
  'col.bytes': 'البايتات',
  'col.query': 'الاستعلام',
  'col.type': 'النوع',
  'col.response': 'الاستجابة',
  'col.server': 'الخادم',
  'col.severity': 'الخطورة',
  'col.reason': 'السبب',
  'col.metadata': 'البيانات الظاهرة',
  'col.sni': 'اسم الخادم (SNI)',
  'col.version': 'الإصدار',
  'col.issuer': 'مُصدِر الشهادة',
  'col.subject': 'موضوع الشهادة',
  'col.level': 'المستوى',
  'col.message': 'الرسالة',
  'col.scope': 'النطاق',

  'value.online': 'متصل',
  'value.offline': 'غير متصل',
  'value.encrypted': 'مشفّر',
  'value.unencrypted': 'غير مشفّر',
  'value.unknown': 'غير معروف',
  'value.up': 'رفع',
  'value.down': 'تنزيل',
  'value.local': 'محلي',

  'action.search': 'بحث',
  'action.refresh': 'تحديث',
  'action.export': 'تصدير',
  'action.clear': 'مسح',
  'action.close': 'إغلاق',
  'action.save': 'حفظ',
  'action.back': 'رجوع',
  'action.acknowledge': 'تأكيد',
  'action.acknowledgeAll': 'تأكيد الكل',
  'action.pauseDevice': 'إيقاف مراقبة الجهاز مؤقتًا',
  'action.resumeDevice': 'استئناف مراقبة الجهاز',
  'action.ignoreDevice': 'تجاهل الجهاز',
  'action.unignoreDevice': 'إلغاء التجاهل',
  'action.details': 'التفاصيل',
  'action.apply': 'تطبيق',
  'action.browse': 'استعراض…',

  'filter.all': 'الكل',
  'filter.encrypted': 'مشفّر',
  'filter.unencrypted': 'غير مشفّر',
  'filter.upload': 'رفع',
  'filter.download': 'تنزيل',

  'range.1m': 'آخر دقيقة',
  'range.5m': 'آخر ٥ دقائق',
  'range.15m': 'آخر ١٥ دقيقة',
  'range.1h': 'آخر ساعة',
  'range.24h': 'آخر ٢٤ ساعة',
  'range.7d': 'آخر ٧ أيام',
  'range.30d': 'آخر ٣٠ يومًا',

  'empty.noData': 'لا توجد بيانات بعد',
  'empty.startMonitoring': 'ابدأ المراقبة لجمع البيانات.',
  'empty.noResults': 'لا نتائج مطابقة لهذا التصفية.',
  'empty.unencrypted': 'لم تُرصد أي حركة غير مشفّرة.',
  'empty.alerts': 'لا توجد تنبيهات.',

  'unenc.title': 'الحركة غير المشفّرة',
  'unenc.explain':
    'هذه البروتوكولات ترسل محتواها بشكل واضح على الشبكة. تُعرض البيانات الوصفية غير الحساسة فقط — لا تُجمع كلمات المرور ولا ملفات تعريف الارتباط ولا الرموز ولا محتوى الرسائل إطلاقًا.',
  'unenc.redacted': '[بيانات حساسة محجوبة]',

  'tls.title': 'جلسات HTTPS / TLS',
  'tls.explain':
    'لا يُفك تشفير أي حركة. يُعرض فقط ما يرسله بروتوكول TLS نفسه بشكل ظاهر: اسم الخادم، والإصدار المتفاوض عليه، وأسماء الشهادة عندما تكشفها المصافحة.',

  'dns.title': 'مراقب DNS',
  'dns.clearHistory': 'حذف سجلّ DNS',
  'dns.clearConfirm': 'حذف جميع استعلامات DNS المخزّنة؟ لا يمكن التراجع عن هذا.',

  'pcap.title': 'التقاط الحزم',
  'pcap.explain': 'لا تُكتب أي حزم على القرص إلا أثناء عملية التقاط بدأتها أنت. لا يُسجَّل شيء تلقائيًا.',
  'pcap.start': 'بدء التقاط الحزم',
  'pcap.stop': 'إيقاف التقاط الحزم',
  'pcap.duration': 'أقصى مدة (بالثواني)',
  'pcap.maxSize': 'أقصى حجم للملف (ميغابايت)',
  'pcap.filter': 'مرشّح الالتقاط (BPF)',
  'pcap.output': 'ملف الإخراج',
  'pcap.running': 'جارٍ الالتقاط…',
  'pcap.written': 'المكتوب',

  'settings.interface': 'واجهة الشبكة',
  'settings.capture': 'الالتقاط',
  'settings.retention': 'مدة الاحتفاظ بالبيانات',
  'settings.privacy': 'الخصوصية',
  'settings.notifications': 'الإشعارات',
  'settings.theme': 'المظهر',
  'settings.language': 'اللغة',
  'settings.performance': 'الأداء',
  'settings.logging': 'السجلات',
  'settings.database': 'قاعدة البيانات',
  'settings.privacyMode': 'وضع الخصوصية',
  'settings.privacyModeHelp':
    'يوقف تسجيل أي شيء مستخرج من محتوى الحزم: استعلامات DNS، وبيانات HTTP الوصفية، وأسماء خوادم TLS. تبقى العدّادات والأجهزة والتدفقات تعمل.',
  'settings.storeDns': 'تخزين استعلامات DNS',
  'settings.storeUnencrypted': 'تخزين البيانات الوصفية غير المشفّرة',
  'settings.notifyMin': 'أدنى خطورة للإشعارات',
  'settings.uiRate': 'معدّل تحديث الواجهة (هرتز)',
  'settings.maxLiveFlows': 'أقصى عدد صفوف مباشرة',
  'settings.logLevel': 'مستوى السجل',
  'settings.purge': 'حذف البيانات المخزّنة',
  'settings.purgeAll': 'حذف كل شيء',
  'settings.purgeConfirm': 'حذف هذه البيانات نهائيًا؟',
  'settings.dbSize': 'حجم قاعدة البيانات',
  'settings.telemetry': 'التتبّع معطّل ولا يمكن تفعيله. لا تغادر أي بيانات هذا الجهاز.',

  'env.npcapMissing': 'Npcap مطلوب لمراقبة حركة الشبكة.',
  'env.npcapHelp':
    'ثبّت Npcap من npcap.com مع تفعيل خيار «WinPcap API-compatible mode» أثناء التثبيت، ثم أعد تشغيل blazma.nt.',
  'env.dumpcapMissing': 'لم يُعثر على dumpcap.exe.',
  'env.dumpcapHelp':
    'يلتقط blazma.nt الحزم عبر dumpcap، وهو أداة الالتقاط التي تُثبَّت مع Wireshark. ثبّت Wireshark ثم أعد تشغيل البرنامج.',
  'env.notElevated': 'البرنامج لا يعمل بصلاحيات مدير.',
  'env.ready': 'بيئة الالتقاط جاهزة',

  'legal.notice':
    'راقب فقط الشبكات التي تملكها أو لديك تصريح بمراقبتها. blazma.nt سلبي وللقراءة فقط: لا يحقن ولا ينتحل ولا يعيد توجيه أي حركة.',

  'log.export': 'تصدير السجلات',
  'log.clear': 'مسح السجلات',

  'nav.router': 'التحكم بالراوتر',
  'router.title': 'التحكم بالراوتر',
  'router.subtitle':
    'أوامر تحكّم تُرسَل مباشرة إلى راوترك الذي تملكه عبر واجهته الرسمية — بلا انتحال، بلا حقن، بلا اضطراب للشبكة.',
  'router.detected': 'الراوتر المكتشَف',
  'router.notDetected': 'لم يُكتشف راوتر قابل للتحكم',
  'router.gateway': 'البوابة',
  'router.model': 'الموديل',
  'router.notControllable': 'عُثر على الراوتر لكن لا يوجد تكامل تحكّم له في blazma.nt. المراقبة تعمل كالمعتاد.',
  'router.connect': 'اتصال',
  'router.disconnect': 'قطع الاتصال',
  'router.forget': 'نسيان بيانات الدخول',
  'router.connected': 'متصل',
  'router.disconnected': 'غير متصل',
  'router.connecting': 'جارٍ الاتصال…',
  'router.username': 'اسم مستخدم المدير',
  'router.password': 'كلمة مرور المدير',
  'router.usernameHint': 'غالبًا «admin». هذه بيانات دخول راوترك، تُدخَل داخل blazma.nt فقط.',
  'router.save': 'تذكّر هذا الدخول (مشفّرًا على هذا الجهاز)',
  'router.credentialNote':
    'كلمة مرورك تُشفَّر بمخزن مفاتيح ويندوز ولا تغادر هذا الجهاز إطلاقًا. يستخدمها blazma.nt فقط لتسجيل الدخول إلى راوترك.',
  'router.devices': 'الأجهزة على الراوتر',
  'router.block': 'قطع النت',
  'router.unblock': 'إعادة النت',
  'router.blocked': 'محظور',
  'router.online': 'متصل',
  'router.offline': 'غير متصل',
  'router.self': 'هذا الجهاز',
  'router.blockConfirm': 'قطع هذا الجهاز عن الشبكة عبر الراوتر؟ يمكنك إعادته في أي وقت.',
  'router.blockSelfConfirm':
    'هذا هو الجهاز الذي يعمل عليه blazma.nt. حظره سيقطع نتك أنت، وقد تفقد الوصول إلى الراوتر. هل تكمل؟',
  'router.rebootConfirm': 'إعادة تشغيل الراوتر الآن؟ سيفقد كل من على الشبكة الاتصال لدقيقة تقريبًا.',
  'router.reboot': 'إعادة تشغيل الراوتر',
  'router.dns': 'DNS الراوتر',
  'router.dnsPrimary': 'DNS الأساسي',
  'router.dnsSecondary': 'DNS الثانوي',
  'router.dnsAuto': 'تلقائي (من المشغّل)',
  'router.dnsApply': 'تطبيق DNS',
  'router.dnsNote': 'تغيير DNS هنا يؤثّر على كل جهاز يأخذ إعداداته من الراوتر.',
  'router.signal': 'الإشارة',
  'router.network': 'الشبكة',
  'router.operator': 'المشغّل',
  'router.refresh': 'تحديث',
  'router.noDevices': 'لم يُبلّغ الراوتر عن أي أجهزة بعد.',
  'router.warnActive': 'هذه أدوات تحكّم فعّالة. حظر جهاز يقطعه فعليًا؛ وإعادة التشغيل تُسقط كل الاتصالات.',

  'err.E_NPCAP_MISSING':
    'Npcap مطلوب لمراقبة حركة الشبكة. ثبّت Npcap من npcap.com مع تفعيل خيار «WinPcap API-compatible mode»، ثم أعد تشغيل blazma.nt.',
  'err.E_DUMPCAP_MISSING':
    'لم يُعثر على dumpcap.exe. ثبّت Wireshark، فهو يوفّر أداة الالتقاط التي يستخدمها blazma.nt فوق Npcap.',
  'err.E_IFACE_NOT_CAPTURABLE': 'هذه البطاقة لا تملك جهاز التقاط Npcap. اختر واجهة موسومة بأنها قابلة للالتقاط.',
  'err.E_IFACE_UNKNOWN': 'الواجهة المختارة لم تعد موجودة. حدّث قائمة الواجهات.',
  'err.E_ALREADY_RUNNING': 'المراقبة تعمل بالفعل. أوقفها قبل اختيار واجهة أخرى.',
  'err.E_CAPTURE_FAILED': 'تعذّر بدء الالتقاط.',
  'err.E_CAPTURE_ENDED': 'توقّف الالتقاط بشكل غير متوقّع.',
  'err.E_ROUTER_UNSUPPORTED': 'هذا الراوتر غير قابل للتحكم عبر blazma.nt.',
  'err.E_ROUTER_LOGIN': 'فشل تسجيل الدخول إلى الراوتر. تحقّق من اسم المستخدم وكلمة المرور.',
  'err.E_ROUTER_NOT_CONNECTED': 'غير متصل بالراوتر. اتصل أولًا.',
  'err.E_ROUTER_ACTION': 'رفض الراوتر الطلب.'
}

const TABLES: Record<Language, Record<TranslationKey, string>> = { en, ar }

export function translator(language: Language): (key: TranslationKey) => string {
  const table = TABLES[language] ?? en
  return (key) => table[key] ?? en[key] ?? key
}

/**
 * Turns a backend message into displayable text. Coded errors are translated;
 * anything else (a raw OS or tool message) is shown as it came, because an
 * approximate translation of a diagnostic is worse than the original.
 */
export function translateError(message: string, language: Language): string {
  const { code, text } = parseCoded(message)
  if (!code) return text
  const key = `err.${code}` as TranslationKey
  const translated = (TABLES[language] ?? en)[key]
  if (!translated) return text
  // For failures that wrap a tool's own diagnostic, keep that detail appended.
  if ((code === 'E_CAPTURE_FAILED' || code === 'E_CAPTURE_ENDED') && text) {
    return `${translated} ${text}`
  }
  return translated
}

export function isRtl(language: Language): boolean {
  return language === 'ar'
}
