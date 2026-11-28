//! Localized English and Ukrainian copy for [`crate::support_report`].

use super::{ReadinessLevel, SupportAudience, SupportLang};

pub fn report_title(lang: SupportLang, aud: SupportAudience) -> &'static str {
    match (lang, aud) {
        (SupportLang::En, SupportAudience::Isp) => "Network Connection Diagnostic Report — ISP Escalation",
        (SupportLang::En, SupportAudience::Landlord) => "Apartment Wi-Fi & Line Diagnostic Summary",
        (SupportLang::En, SupportAudience::Admin) => "Local Network & Router Audit Pack",
        (SupportLang::Uk, SupportAudience::Isp) => "Діагностичний звіт підключення — звернення до провайдера",
        (SupportLang::Uk, SupportAudience::Landlord) => "Стислий діагностичний звіт Wi-Fi та лінії для орендодавця",
        (SupportLang::Uk, SupportAudience::Admin) => "Технічний аудит локальної мережі та роутера",
    }
}

pub fn audience_label(lang: SupportLang, aud: SupportAudience) -> &'static str {
    match (lang, aud) {
        (SupportLang::En, SupportAudience::Isp) => "ISP Support",
        (SupportLang::En, SupportAudience::Landlord) => "Landlord",
        (SupportLang::En, SupportAudience::Admin) => "Network Admin",
        (SupportLang::Uk, SupportAudience::Isp) => "Підтримка провайдера",
        (SupportLang::Uk, SupportAudience::Landlord) => "Орендодавець",
        (SupportLang::Uk, SupportAudience::Admin) => "Адміністратор мережі",
    }
}

pub fn readiness_label(lang: SupportLang, lv: ReadinessLevel) -> &'static str {
    match (lang, lv) {
        (SupportLang::En, ReadinessLevel::High) => "High confidence",
        (SupportLang::En, ReadinessLevel::Medium) => "Medium confidence",
        (SupportLang::En, ReadinessLevel::Low) => "Low confidence / preliminary",
        (SupportLang::Uk, ReadinessLevel::High) => "Висока доказовість",
        (SupportLang::Uk, ReadinessLevel::Medium) => "Середня доказовість",
        (SupportLang::Uk, ReadinessLevel::Low) => "Низька доказовість / попередній звіт",
    }
}

pub fn status_good(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Good",
        SupportLang::Uk => "Добре",
    }
}

pub fn status_degraded(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Degraded",
        SupportLang::Uk => "Погіршено",
    }
}

pub fn status_poor(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Poor",
        SupportLang::Uk => "Погано",
    }
}

pub fn methodology_lines(lang: SupportLang, tick_s: f64, wired: bool, wifi: bool, ntp: bool) -> Vec<String> {
    let paths = match (lang, wired, wifi) {
        (SupportLang::En, true, true) => "parallel wired Ethernet and Wi-Fi monitoring against the same router",
        (SupportLang::En, true, false) => "wired Ethernet monitoring at the router",
        (SupportLang::En, false, true) => "Wi-Fi path monitoring",
        (SupportLang::En, false, false) => "passive session telemetry",
        (SupportLang::Uk, true, true) => "паралельний моніторинг по кабелю Ethernet та Wi-Fi до одного роутера",
        (SupportLang::Uk, true, false) => "кабельний моніторинг Ethernet біля роутера",
        (SupportLang::Uk, false, true) => "моніторинг через Wi-Fi",
        (SupportLang::Uk, false, false) => "пасивна телеметрія сеансу",
    };
    let clock = match (lang, ntp) {
        (SupportLang::En, true) => "NTP-synchronised UTC and local timestamps",
        (SupportLang::En, false) => "UTC and local timestamps (NTP unsynchronised on at least one host)",
        (SupportLang::Uk, true) => "синхронізовані через NTP мітки часу UTC і місцевого часу",
        (SupportLang::Uk, false) => "мітки часу UTC і місцевого часу (NTP не синхронізовано щонайменше на одному хості)",
    };
    match lang {
        SupportLang::En => vec![
            format!("Continuous {tick_s:.1}s direct ICMP, TCP, and DNS probes with {paths}."),
            format!("Recorded with {clock}; observer host faults and own speedtest load spikes separated from unprovoked network outages."),
            "Every metric and timestamp comes directly from reproducible per-second session logs.".into(),
        ],
        SupportLang::Uk => vec![
            format!("Безперервні прямі ICMP-, TCP- та DNS-перевірки кожні {tick_s:.1} с: {paths}."),
            format!("Використані {clock}; збої самого пристрою-спостерігача та короткі просідання під власним тестом швидкості відокремлено від неспровокованих збоїв мережі."),
            "Усі числа та мітки часу взято безпосередньо з похвилинних і посекундних журналів сеансу.".into(),
        ],
    }
}

pub fn warn_no_sessions(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "No recorded session data found for this pack.",
        SupportLang::Uk => "Для цього звіту не знайдено записаних даних сеансу.",
    }
}

pub fn warn_network_mismatch(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Selected sessions belong to different networks; cross-session ISP line attribution is disabled.",
        SupportLang::Uk => "Вибрані сеанси належать до різних мереж; спільні висновки щодо лінії провайдера вимкнено.",
    }
}

pub fn warn_short_run(lang: SupportLang, hours: f64) -> String {
    match lang {
        SupportLang::En => format!("Short capture ({hours:.1} h < 2 h): treat as preliminary or emergency evidence."),
        SupportLang::Uk => format!("Короткий замір ({hours:.1} год < 2 год): використовуйте як попередні або екстрені докази."),
    }
}

pub fn warn_wifi_only_for_isp(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Wi-Fi-only test: ISP support may attribute drops to local wireless interference. Add a wired Ethernet run if possible.",
        SupportLang::Uk => "Тест лише по Wi-Fi: підтримка провайдера може списати обриви на бездротові завади. Бажано додати замір по кабелю Ethernet.",
    }
}

pub fn warn_power_save(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Wi-Fi power-save was enabled on the monitor host, adding local latency jitter.",
        SupportLang::Uk => "На пристрої спостерігача було ввімкнено енергозбереження Wi-Fi, що додає локальні затримки.",
    }
}

pub fn warn_ntp_unsynced(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Host clock was not NTP-synchronised during part of the capture; correlate external logs cautiously.",
        SupportLang::Uk => "Годинник хоста не був синхронізований по NTP; зіставляйте зовнішні журнали з урахуванням можливого зсуву.",
    }
}

pub fn warn_monitor_gaps(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Monitor gaps or host sleep periods occurred; those gaps are excluded from uptime claims.",
        SupportLang::Uk => "Під час виміру були паузи або сон хоста; ці інтервали виключені з розрахунку.",
    }
}

pub fn warn_isp_line_healthy_wifi_only(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "ISP line is healthy (~100% wired Ethernet availability): do NOT file an ISP line outage ticket. Escalate indoor Wi-Fi coverage to landlord or admin instead.",
        SupportLang::Uk => "Лінія провайдера справна (~100% доступність по кабелю Ethernet): НЕ подавайте заявку на обрив лінії провайдеру. Натомість адресуйте проблему покриття Wi-Fi орендодавцю чи адміну.",
    }
}

pub fn warn_observer_polluted(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "The measuring device itself was unreliable for a large part of the run (late probe ticks or throttling): fix the host and measure again before filing a ticket.",
        SupportLang::Uk => "Сам вимірювальний пристрій був ненадійним значну частину часу (запізнілі такти проб або троттлінг): виправте хост і виміряйте знову, перш ніж подавати заявку.",
    }
}

pub fn warn_load_provoked_only(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "All drops happened strictly during own heavy load/speedtest (bufferbloat): do NOT file an unprovoked ISP outage ticket.",
        SupportLang::Uk => "Усі короткі збої стались лише під час власного тесту швидкості (bufferbloat): НЕ подавайте заявку про спонтанні обриви лінії.",
    }
}

pub fn warn_rogue_dhcp_local(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Secondary/rogue DHCP server detected on LAN: fix locally inside the building before contacting the ISP.",
        SupportLang::Uk => "У локальній мережі виявлено сторонній DHCP-сервер: усуньте це всередині мережі до звернення до провайдера.",
    }
}

pub fn ro_wired(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Tested directly via wired Ethernet at the router.",
        SupportLang::Uk => "Протестовано напряму по кабелю Ethernet біля роутера.",
    }
}

pub fn ro_ntp(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "System clock verified NTP-synchronised.",
        SupportLang::Uk => "Системний годинник синхронізовано по NTP.",
    }
}

pub fn ro_power_save_off(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Wi-Fi power-save disabled on monitor adapter.",
        SupportLang::Uk => "Енергозбереження Wi-Fi адаптера вимкнено.",
    }
}

pub fn ro_router_uptime(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Router showed continuous WAN uptime with 0 reboots.",
        SupportLang::Uk => "Роутер працював безперервно: 0 перезавантажень WAN.",
    }
}

pub fn ro_host_uptime(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Monitor host remained awake with continuous uptime and no power interruption.",
        SupportLang::Uk => "Хост спостерігача не засинав і працював без перебоїв живлення.",
    }
}

pub fn ro_observer_excluded(lang: SupportLang, count: u32) -> String {
    match lang {
        SupportLang::En => format!("Observer-device events ({count}) isolated and excluded from network counts."),
        SupportLang::Uk => format!("Інциденти пристрою-спостерігача ({count}) відокремлено й виключено з мережевої статистики."),
    }
}

pub fn ro_load_excluded(lang: SupportLang, count: u32) -> String {
    match lang {
        SupportLang::En => format!("Short load spikes during own speedtest ({count}) separated from idle outages."),
        SupportLang::Uk => format!("Короткі збої під час власного тесту швидкості ({count}) відділено від фонових обривів."),
    }
}

pub fn ask_rogue_dhcp_sum(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Locate and disconnect unauthorized DHCP server / second router LAN port on local network",
        SupportLang::Uk => "Знайдіть та вимкніть сторонній DHCP-сервер або неправильно підключений другий роутер у локальній мережі",
    }
}

pub fn ask_rogue_dhcp_rat(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Security detector recorded a second DHCP gateway offering leases on LAN. Clients alternate between routers and lose internet even when the ISP line is fine.",
        SupportLang::Uk => "Детектор безпеки зафіксував другий DHCP-шлюз у локальній мережі. Клієнти отримують чужий маршрут і втрачають інтернет навіть при справній лінії.",
    }
}

pub fn ask_isp_line_sum(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Escalate to L2/NOC to inspect access line, CMTS/ONT signal/T3-T4 counters at listed UTC timestamps",
        SupportLang::Uk => "Передайте заявку до L2/NOC для перевірки лінії доступу та лічильників на вузлі в наведені UTC-вікна",
    }
}

pub fn ask_isp_line_rat(lang: SupportLang, n: u32, has_docsis: bool) -> String {
    match (lang, has_docsis) {
        (SupportLang::En, true) => format!("{n} unprovoked upstream/line outage(s) hit wired Ethernet and Wi-Fi together while router LAN answered normally, matching DOCSIS event log entries."),
        (SupportLang::En, false) => format!("{n} unprovoked upstream/line outage(s) hit wired Ethernet and Wi-Fi together while router LAN answered normally; issue is intermittent beyond the router."),
        (SupportLang::Uk, true) => format!("Зафіксовано {n} неспровокованих збоїв лінії/провайдера одночасно на кабелі та Wi-Fi при живому локальному роутері, що збігається з журналом модема."),
        (SupportLang::Uk, false) => format!("Зафіксовано {n} неспровокованих збоїв лінії/провайдера одночасно на кабелі та Wi-Fi при стабільному роутері."),
    }
}

pub fn ask_router_sum(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Inspect or replace router/gateway hardware or firmware (LAN stalls / reboots observed)",
        SupportLang::Uk => "Перевірте або замініть роутер чи його блок живлення/прошивку (фіксуються збої або ребути шлюзу)",
    }
}

pub fn ask_router_rat(lang: SupportLang, inc: u32, resets: u32, host_up: bool) -> String {
    match (lang, host_up) {
        (SupportLang::En, true) => format!("Router failed to answer on LAN {inc} time(s) and reset WAN uptime {resets} time(s) while monitor host kept continuous uptime on the same mains power."),
        (SupportLang::En, false) => format!("Router failed to answer on LAN {inc} time(s) and recorded {resets} WAN uptime reset(s)."),
        (SupportLang::Uk, true) => format!("Роутер не відповідав у локальній мережі ({inc} разів) або перезавантажувався ({resets} разів), хоча хост на тій самій розетці працював безперервно."),
        (SupportLang::Uk, false) => format!("Роутер не відповідав у LAN ({inc} разів) і зафіксував {resets} перезавантажень WAN."),
    }
}

pub fn ask_dns_sum(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Verify upstream DNS resolvers (IP probes stayed online while DNS timed out)",
        SupportLang::Uk => "Перевірте DNS-сервери провайдера або змініть DNS у DHCP роутера (IP-пінги проходили, а DNS зависав)",
    }
}

pub fn ask_dns_rat(lang: SupportLang, n: u32) -> String {
    match lang {
        SupportLang::En => format!("{n} incident(s) failed DNS name resolution while direct IPv4/TCP probes to external targets kept answering."),
        SupportLang::Uk => format!("Зафіксовано {n} збоїв DNS при 100% доступності прямих IP/TCP цілей."),
    }
}

pub fn ask_bufferbloat_sum(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Enable SQM/AQM queue management or enable modem/bridge mode with an SQM-capable router",
        SupportLang::Uk => "Увімкніть SQM/AQM керування чергами або переведіть модем у режим моста з SQM-роутером",
    }
}

pub fn ask_bufferbloat_rat(lang: SupportLang, loaded: Option<f64>, idle: Option<f64>, load_inc: u32) -> String {
    let l = loaded.map_or("-".into(), |v| format!("{v:.0} ms"));
    let i = idle.map_or("-".into(), |v| format!("{v:.0} ms"));
    match lang {
        SupportLang::En => format!("Latency jumped under saturation load (loaded median {l} vs idle {i}; {load_inc} brief speedtest-coincident drop(s)), causing interactive calls/games to freeze during downloads."),
        SupportLang::Uk => format!("Під завантаженням каналу затримка різко зростала (медіана під навантаженням {l} проти {i} у спокої; {load_inc} коротких збоїв лише на піку тесту швидкості)."),
    }
}

pub fn ask_evening_congestion_sum(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Investigate peak-evening upstream capacity/node congestion (18:00–24:00) on wired baseline",
        SupportLang::Uk => "Перевірте вечірнє перевантаження вузла доступу провайдера (18:00–24:00) — підтверджено по кабелю",
    }
}

pub fn ask_evening_congestion_rat(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Wired throughput and/or latency degraded significantly in peak hours without any corresponding surge in active household devices.",
        SupportLang::Uk => "Швидкість або затримка на кабелі суттєво погіршуються ввечері без зростання кількості активних пристроїв у квартирі.",
    }
}

pub fn ask_landlord_poe_sum(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Install one wired PoE access point in the central hallway, powered from the existing kitchen socket next to the router",
        SupportLang::Uk => "Встановіть одну дротову точку доступу PoE у центральному коридорі, зажививши її від існуючої розетки біля роутера на кухні",
    }
}

pub fn ask_landlord_poe_rat(lang: SupportLang, max_walls: Option<u32>, max_loss: Option<f64>) -> String {
    let geom = match (lang, max_walls, max_loss) {
        (SupportLang::En, Some(w), Some(db)) if w > 0 => format!(" Current corner placement forces Wi-Fi through up to {w} interior wall(s) (~{db:.0} dB loss)."),
        (SupportLang::Uk, Some(w), Some(db)) if w > 0 => format!(" Через розташування в кутку сигнал долає до {w} стін (~{db:.0} дБ втрат)."),
        _ => String::new(),
    };
    match lang {
        SupportLang::En => format!("Wired Ethernet is clean, proving the ISP line works properly; drops occur indoors over Wi-Fi.{geom} A PoE injector next to the router sends both data and low-voltage power over one thin Ethernet cable into the hallway, so zero power socket or electrical work is needed in the hallway."),
        SupportLang::Uk => format!("Кабельний тест стабільний — інтернет-лінія працює добре, проблема саме у внутрішньому Wi-Fi.{geom} PoE-інжектор біля роутера на кухні подає і дані, і безпечне живлення по одному тонкому кабелю — розетка в коридорі взагалі не потрібна."),
    }
}

pub fn ask_landlord_no_repeater_sum(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Avoid plug-in wireless Wi-Fi repeaters/extenders",
        SupportLang::Uk => "Уникайте звичайних бездротових Wi-Fi підсилювачів (репітерів) у розетку",
    }
}

pub fn ask_landlord_no_repeater_rat(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Wireless repeaters retransmit every packet on the same radio channel, roughly halving airtime and worsening micro-drops for nearby apartments.",
        SupportLang::Uk => "Бездротові репітери повторно передають кожен пакет на тому ж каналі, удвічі зменшуючи пропускну здатність і посилюючи затримки та конфлікти в сусідніх квартирах.",
    }
}

pub fn ask_admin_wifi_sum(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Reposition AP centrally and select clean 5 GHz channel / lower co-channel contention",
        SupportLang::Uk => "Перенесіть точку доступу в центр та переведіть на менш завантажений 5 ГГц канал",
    }
}

pub fn ask_admin_wifi_rat(lang: SupportLang, worst_sig: Option<f64>, retries: Option<f64>) -> String {
    let s = worst_sig.map_or("-".into(), |v| format!("{v:.0} dBm"));
    let r = retries.map_or("-".into(), |v| format!("{v:.0}/min"));
    match lang {
        SupportLang::En => format!("Observed indoor Wi-Fi degradation (weakest median signal {s}, max TX retries {r}) while wired path remained healthy."),
        SupportLang::Uk => format!("Локальна деградація Wi-Fi (найслабша медіана сигналу {s}, макс. повторів {r}) при здоровому кабелі."),
    }
}

pub fn ask_sec_hardening_sum(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Close exposed insecure router LAN services and patch firmware CVEs",
        SupportLang::Uk => "Закрийте небезпечні сервіси на LAN-інтерфейсі роутера та оновіть прошивку проти відомих CVE",
    }
}

pub fn ask_sec_hardening_rat(lang: SupportLang, ports: &[String], cves: usize, kevs: usize) -> String {
    let p = if ports.is_empty() { "-".to_string() } else { ports.join(", ") };
    match lang {
        SupportLang::En => format!("Router audit detected exposed LAN service(s) [{p}] and {cves} matched CVE(s) ({kevs} CISA KEV). Disable Telnet/FTP/plain-HTTP admin and install security updates."),
        SupportLang::Uk => format!("Аудит роутера виявив відкриті сервіси [{p}] та {cves} відомих CVE (із них KEV: {kevs}). Вимкніть Telnet/FTP/HTTP-адмінку та оновіть прошивку."),
    }
}

pub fn sec_passive_scope_only(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Scope note: only passive beacon/probe telemetry is included; active router admin login audit was not run.",
        SupportLang::Uk => "Межі перевірки: використано лише пасивну телеметрію ефіру та зондів; активний аудит веб-інтерфейсу роутера не запускався.",
    }
}

pub fn finding_household_evening_surge(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Note: evening latency/throughput shift coincides with increased active household device count, so local traffic sharing contributes to peak load.",
        SupportLang::Uk => "Примітка: вечірні коливання збігаються зі зростанням числа активних пристроїв у мережі — локальне навантаження частково пояснює просідання.",
    }
}

#[allow(clippy::too_many_arguments)]
pub fn before_after_summary(
    lang: SupportLang,
    label: &str,
    a1: f64,
    a2: f64,
    o1: u32,
    o2: u32,
    s1: Option<f64>,
    s2: Option<f64>,
    r1: Option<f64>,
    r2: Option<f64>,
) -> String {
    let sig_part = match (s1, s2) {
        (Some(x), Some(y)) => format!(", Wi-Fi {x:.0} → {y:.0} dBm"),
        _ => String::new(),
    };
    let ret_part = match (lang, r1, r2) {
        (SupportLang::En, Some(x), Some(y)) => format!(", retries {x:.0} → {y:.0}/min"),
        (SupportLang::Uk, Some(x), Some(y)) => format!(", повтори {x:.0} → {y:.0}/хв"),
        _ => String::new(),
    };
    match lang {
        SupportLang::En => format!("Before/After check ({label}): availability {a1:.2}% → {a2:.2}%, outages {o1} → {o2}{sig_part}{ret_part}."),
        SupportLang::Uk => format!("Перевірка «До / Після» ({label}): доступність {a1:.2}% → {a2:.2}%, обривів {o1} → {o2}{sig_part}{ret_part}."),
    }
}

pub fn headline_mismatch(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Sessions come from different networks — compare metrics separately before filing one ticket.",
        SupportLang::Uk => "Сеанси записано в різних мережах — оцінюйте їх окремо до подачі спільного звернення.",
    }
}

pub fn headline_rogue_dhcp(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "A secondary DHCP server/router was detected on the LAN — fix local wiring before blaming the ISP.",
        SupportLang::Uk => "У локальній мережі виявлено сторонній DHCP-сервер або другий роутер — усуньте це локально до звернення до провайдера.",
    }
}

pub fn headline_wifi_only(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "The ISP cable connection at the router is stable (~100%); drops occur indoors over Wi-Fi due to walls and corner placement.",
        SupportLang::Uk => "Кабельне підключення від провайдера на роутері стабільне (~100%); збої виникають усередині квартири на Wi-Fi через стіни та кутове розміщення.",
    }
}

pub fn headline_load_only(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "All monitored paths remained healthy when idle; brief stalls occurred only under full download saturation (bufferbloat).",
        SupportLang::Uk => "У стані спокою мережа стабільна; короткі зависання виникали лише під максимальним завантаженням каналу (bufferbloat).",
    }
}

pub fn headline_line_fault(lang: SupportLang, n: u32) -> String {
    match lang {
        SupportLang::En => format!("Measured {n} unprovoked upstream/ISP outage(s) simultaneously across Ethernet and Wi-Fi while local router stayed responsive."),
        SupportLang::Uk => format!("Зафіксовано {n} неспровокованих збоїв лінії провайдера одночасно на кабелі та Wi-Fi при справному локальному роутері."),
    }
}

pub fn headline_router_fault(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Router/gateway stopped answering locally or rebooted across monitored paths.",
        SupportLang::Uk => "Роутер/шлюз переставав відповідати в локальній мережі або перезавантажувався на всіх шляхах.",
    }
}

pub fn headline_dns_fault(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "Direct IP connectivity worked cleanly, while DNS name resolution repeatedly timed out.",
        SupportLang::Uk => "Прямі IP-з'єднання працювали стабільно, тоді як DNS-перевірки регулярно зависали.",
    }
}

pub fn headline_healthy(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::En => "All monitored paths ran cleanly with no unprovoked outage pattern detected.",
        SupportLang::Uk => "Усі перевірені шляхи працювали стабільно без системних обривів.",
    }
}

pub fn sec_headings(lang: SupportLang) -> Headings {
    match lang {
        SupportLang::En => Headings {
            audience: "Audience",
            readiness: "Evidence readiness",
            ruled_out: "Already ruled out",
            asks: "Requested actions",
            findings: "Key findings",
            points: "Measured rooms / points",
            incidents: "Unprovoked incident log (UTC & local)",
            security: "Security & scope notes",
            free_notes: "Free-text session notes (untranslated)",
            method: "Measurement methodology",
            no_incidents: "No unprovoked network outages recorded.",
        },
        SupportLang::Uk => Headings {
            audience: "Отримувач",
            readiness: "Рівень доказовості",
            ruled_out: "Що вже виключено",
            asks: "Конкретні прохання та дії",
            findings: "Ключові висновки",
            points: "Порівняння точок / кімнат",
            incidents: "Журнал неспровокованих збоїв (UTC та місцевий час)",
            security: "Безпека та межі перевірки",
            free_notes: "Нотатки користувача (без автоперекладу)",
            method: "Методологія вимірів",
            no_incidents: "Неспровокованих мережевих обривів не зафіксовано.",
        },
    }
}

pub struct Headings {
    pub audience: &'static str,
    pub readiness: &'static str,
    pub ruled_out: &'static str,
    pub asks: &'static str,
    pub findings: &'static str,
    pub points: &'static str,
    pub incidents: &'static str,
    pub security: &'static str,
    pub free_notes: &'static str,
    pub method: &'static str,
    pub no_incidents: &'static str,
}
