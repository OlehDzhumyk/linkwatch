//! Renderers for [`SupportPack`]: Layer 1 plain ticket text (`<= 2000` chars),
//! Layer 2 structured Markdown, and self-contained offline printable HTML (`@media print`).

use super::{SupportLang, SupportPack, i18n};
use std::fmt::Write;

const SHORT_TEXT_LIMIT: usize = 2000;

/// Layer 1 copy-paste ticket summary guaranteed `<= 2000` Unicode scalar characters.
pub fn render_short_text(pack: &SupportPack) -> String {
    let h = i18n::sec_headings(pack.lang);
    let mut s = String::new();
    let _ = writeln!(s, "{}", pack.title);
    let _ = writeln!(
        s,
        "{}: {} ({})",
        h.readiness,
        i18n::readiness_label(pack.lang, pack.readiness.level),
        i18n::audience_label(pack.lang, pack.audience)
    );
    let _ = writeln!(s, "\n{}", pack.verdict_headline);

    if !pack.readiness.warnings.is_empty() {
        for w in &pack.readiness.warnings {
            let _ = writeln!(s, "! {w}");
        }
    }

    if !pack.ruled_out.items.is_empty() {
        let _ = writeln!(s, "\n{}:", h.ruled_out);
        for r in pack.ruled_out.items.iter().take(6) {
            let _ = writeln!(s, "[x] {r}");
        }
    }

    if !pack.asks.is_empty() {
        let _ = writeln!(s, "\n{}:", h.asks);
        for (i, a) in pack.asks.iter().take(3).enumerate() {
            let _ = writeln!(s, "{}. {}", i + 1, a.summary);
        }
    }

    if !pack.incidents.is_empty() {
        let _ = writeln!(s, "\n{}:", h.incidents);
        for inc in pack.incidents.iter().take(5) {
            let _ = writeln!(
                s,
                "- {} ({}) · {} {:.0}s [{}]",
                inc.start_utc, inc.start_local, inc.iface, inc.duration_s, inc.cause
            );
        }
    } else if !pack.points.is_empty() {
        let _ = writeln!(s, "\n{}:", h.points);
        for p in pack.points.iter().take(6) {
            let sig = p.signal_med.map_or_else(String::new, |v| format!(", {v:.0} dBm"));
            let _ = writeln!(s, "- {}: {:.2}% ({}{sig})", p.label, p.availability_pct, p.status);
        }
    }

    if let Some(m) = pack.methodology.first() {
        let _ = write!(s, "\n{m}");
    }

    truncate_chars(s.trim(), SHORT_TEXT_LIMIT)
}

fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let keep = max.saturating_sub(1);
    let mut out: String = text.chars().take(keep).collect();
    // Avoid breaking inside the last word if a whitespace boundary sits close by.
    if let Some(ws) = out.rfind(|c: char| c.is_whitespace())
        && ws > keep.saturating_sub(48)
    {
        out.truncate(ws);
    }
    out.push('…');
    out
}

/// Layer 2 Markdown attachment with UTC+local incident table and Markdown table escaping.
pub fn render_markdown(pack: &SupportPack) -> String {
    let h = i18n::sec_headings(pack.lang);
    let mut s = String::new();
    let _ = writeln!(s, "# {}\n", pack.title);
    let _ = writeln!(
        s,
        "**{}:** {} · **{}:** {}\n",
        h.audience,
        i18n::audience_label(pack.lang, pack.audience),
        h.readiness,
        i18n::readiness_label(pack.lang, pack.readiness.level)
    );
    let _ = writeln!(s, "{}\n", pack.verdict_headline);

    if !pack.readiness.warnings.is_empty() {
        for w in &pack.readiness.warnings {
            let _ = writeln!(s, "> **Note:** {w}");
        }
        s.push('\n');
    }

    let _ = writeln!(s, "## {}\n", h.method);
    for m in &pack.methodology {
        let _ = writeln!(s, "- {m}");
    }

    if !pack.ruled_out.items.is_empty() {
        let _ = writeln!(s, "\n## {}\n", h.ruled_out);
        for item in &pack.ruled_out.items {
            let _ = writeln!(s, "- [x] {item}");
        }
    }

    if !pack.asks.is_empty() {
        let _ = writeln!(s, "\n## {}\n", h.asks);
        for a in &pack.asks {
            let _ = writeln!(s, "- **{}** — {}", a.summary, a.rationale);
            if !a.evidence_timestamps.is_empty() {
                let _ = writeln!(s, "  - Timestamps: {}", a.evidence_timestamps.join(", "));
            }
        }
    }

    if !pack.findings.is_empty() {
        let _ = writeln!(s, "\n## {}\n", h.findings);
        for f in &pack.findings {
            let _ = writeln!(s, "- {f}");
        }
    }

    if !pack.points.is_empty() {
        let _ = writeln!(s, "\n## {}\n", h.points);
        let _ = writeln!(s, "| Point | Path | Hours | Avail | Outages/h | Router RTT | Net RTT (idle / load) | Wi-Fi | RF path | Status |");
        let _ = writeln!(s, "|---|---|---|---|---|---|---|---|---|---|");
        for p in &pack.points {
            let net = match (p.net_rtt_med, p.loaded_net_rtt_med) {
                (Some(a), Some(b)) => format!("{a:.1} / {b:.1} ms"),
                (Some(a), None) => format!("{a:.1} ms"),
                _ => "-".into(),
            };
            let wifi = match (p.signal_med, p.retry_rate_per_min) {
                (Some(sig), Some(ret)) => format!("{sig:.0} dBm ({ret:.0}/min)"),
                (Some(sig), None) => format!("{sig:.0} dBm"),
                _ => "-".into(),
            };
            let rf = match (p.distance_m, p.walls_crossed, p.obstacle_loss_db) {
                (Some(d), Some(w), Some(db)) => format!("{d:.1} m, {w}w (-{db:.0} dB)"),
                _ => "-".into(),
            };
            let _ = writeln!(
                s,
                "| {} | {} | {:.1} | {:.2}% | {:.2} | {} | {} | {} | {} | {} |",
                md_cell(&p.label),
                md_cell(&p.iface),
                p.hours,
                p.availability_pct,
                p.outages_per_h,
                p.gw_rtt_med.map_or("-".into(), |v| format!("{v:.1} ms")),
                net,
                wifi,
                rf,
                md_cell(&p.status),
            );
        }
    }

    let _ = writeln!(s, "\n## {}\n", h.incidents);
    if pack.incidents.is_empty() {
        let _ = writeln!(s, "_{}_\n", h.no_incidents);
    } else {
        let _ = writeln!(s, "| Start (UTC) | Local time | Dur (s) | Path | State | Cause | Detail |");
        let _ = writeln!(s, "|---|---|---|---|---|---|---|");
        for inc in &pack.incidents {
            let _ = writeln!(
                s,
                "| {} | {} | {:.0} | {} | {} | {} | {} |",
                md_cell(&inc.start_utc),
                md_cell(&inc.start_local),
                inc.duration_s,
                md_cell(&inc.iface),
                md_cell(&inc.state),
                md_cell(&inc.cause),
                md_cell(&inc.detail),
            );
        }
    }

    if !pack.security_notes.is_empty() {
        let _ = writeln!(s, "\n## {}\n", h.security);
        for n in &pack.security_notes {
            let _ = writeln!(s, "- {n}");
        }
    }

    if !pack.free_text_notes.is_empty() {
        let _ = writeln!(s, "\n## {}\n", h.free_notes);
        for n in &pack.free_text_notes {
            let _ = writeln!(s, "- {n}");
        }
    }
    s
}

/// Self-contained printable HTML document with `@media print`, strict HTML escaping,
/// zero external assets, and zero JavaScript. Intended for attachment downloads.
pub fn render_html(pack: &SupportPack) -> String {
    let h = i18n::sec_headings(pack.lang);
    let lang_code = match pack.lang {
        SupportLang::En => "en",
        SupportLang::Uk => "uk",
    };
    let mut s = String::new();
    let _ = writeln!(s, "<!doctype html>\n<html lang=\"{lang_code}\">\n<head>\n<meta charset=\"utf-8\">");
    let _ = writeln!(s, "<title>{}</title>", html_esc(&pack.title));
    let _ = writeln!(
        s,
        "<style>
:root {{ --fg:#181b20; --muted:#566070; --bg:#ffffff; --card:#f6f8fa; --border:#d8dee6; --ok:#166534; --warn:#b45309; --bad:#b91c1c; }}
body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; color: var(--fg); background: var(--bg); margin: 28px auto; max-width: 920px; padding: 0 20px; line-height: 1.48; font-size: 14px; }}
h1 {{ font-size: 20px; margin: 0 0 6px; }}
h2 {{ font-size: 15px; margin: 20px 0 8px; border-bottom: 1px solid var(--border); padding-bottom: 4px; }}
.meta {{ color: var(--muted); font-size: 13px; margin-bottom: 14px; }}
.lead {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; font-weight: 600; }}
.warn {{ background: #fffbeb; border: 1px solid #f59e0b; border-radius: 6px; padding: 9px 12px; margin: 8px 0; font-size: 13px; }}
ul {{ margin: 6px 0; padding-left: 20px; }}
li {{ margin: 4px 0; }}
table {{ width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 12.5px; }}
th, td {{ border: 1px solid var(--border); padding: 6px 8px; text-align: left; vertical-align: top; }}
th {{ background: var(--card); font-weight: 600; }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }}
@media print {{ body {{ margin: 0; max-width: none; padding: 0; }} .lead, th {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }} }}
</style>\n</head>\n<body>"
    );

    let _ = writeln!(s, "<h1>{}</h1>", html_esc(&pack.title));
    let _ = writeln!(
        s,
        "<p class=\"meta\"><strong>{}:</strong> {} &middot; <strong>{}:</strong> {}</p>",
        html_esc(h.audience),
        html_esc(i18n::audience_label(pack.lang, pack.audience)),
        html_esc(h.readiness),
        html_esc(i18n::readiness_label(pack.lang, pack.readiness.level)),
    );
    let _ = writeln!(s, "<p class=\"lead\">{}</p>", html_esc(&pack.verdict_headline));

    for w in &pack.readiness.warnings {
        let _ = writeln!(s, "<div class=\"warn\">{}</div>", html_esc(w));
    }

    let _ = writeln!(s, "<h2>{}</h2><ul>", html_esc(h.method));
    for m in &pack.methodology {
        let _ = writeln!(s, "<li>{}</li>", html_esc(m));
    }
    s.push_str("</ul>\n");

    if !pack.ruled_out.items.is_empty() {
        let _ = writeln!(s, "<h2>{}</h2><ul>", html_esc(h.ruled_out));
        for item in &pack.ruled_out.items {
            let _ = writeln!(s, "<li>&#10003; {}</li>", html_esc(item));
        }
        s.push_str("</ul>\n");
    }

    if !pack.asks.is_empty() {
        let _ = writeln!(s, "<h2>{}</h2><ul>", html_esc(h.asks));
        for a in &pack.asks {
            let _ = writeln!(s, "<li><strong>{}</strong> &mdash; {}", html_esc(&a.summary), html_esc(&a.rationale));
            if !a.evidence_timestamps.is_empty() {
                let ts: Vec<String> = a.evidence_timestamps.iter().map(|t| html_esc(t)).collect();
                let _ = write!(s, " <span class=\"mono\">({})</span>", ts.join(", "));
            }
            s.push_str("</li>\n");
        }
        s.push_str("</ul>\n");
    }

    if !pack.findings.is_empty() {
        let _ = writeln!(s, "<h2>{}</h2><ul>", html_esc(h.findings));
        for f in &pack.findings {
            let _ = writeln!(s, "<li>{}</li>", html_esc(f));
        }
        s.push_str("</ul>\n");
    }

    if !pack.points.is_empty() {
        let _ = writeln!(s, "<h2>{}</h2>", html_esc(h.points));
        s.push_str("<table><thead><tr><th>Point</th><th>Path</th><th>Hours</th><th>Avail</th><th>Outages/h</th><th>Router RTT</th><th>Net RTT</th><th>Wi-Fi</th><th>RF path</th><th>Status</th></tr></thead><tbody>\n");
        for p in &pack.points {
            let net = match (p.net_rtt_med, p.loaded_net_rtt_med) {
                (Some(a), Some(b)) => format!("{a:.1} / {b:.1} ms"),
                (Some(a), None) => format!("{a:.1} ms"),
                _ => "-".into(),
            };
            let wifi = match (p.signal_med, p.retry_rate_per_min) {
                (Some(sig), Some(ret)) => format!("{sig:.0} dBm ({ret:.0}/min)"),
                (Some(sig), None) => format!("{sig:.0} dBm"),
                _ => "-".into(),
            };
            let rf = match (p.distance_m, p.walls_crossed, p.obstacle_loss_db) {
                (Some(d), Some(w), Some(db)) => format!("{d:.1} m, {w}w (-{db:.0} dB)"),
                _ => "-".into(),
            };
            let _ = writeln!(
                s,
                "<tr><td>{}</td><td class=\"mono\">{}</td><td>{:.1}</td><td>{:.2}%</td><td>{:.2}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_esc(&p.label),
                html_esc(&p.iface),
                p.hours,
                p.availability_pct,
                p.outages_per_h,
                html_esc(&p.gw_rtt_med.map_or("-".into(), |v| format!("{v:.1} ms"))),
                html_esc(&net),
                html_esc(&wifi),
                html_esc(&rf),
                html_esc(&p.status),
            );
        }
        s.push_str("</tbody></table>\n");
    }

    let _ = writeln!(s, "<h2>{}</h2>", html_esc(h.incidents));
    if pack.incidents.is_empty() {
        let _ = writeln!(s, "<p>{}</p>", html_esc(h.no_incidents));
    } else {
        s.push_str("<table><thead><tr><th>Start (UTC)</th><th>Local time</th><th>Dur (s)</th><th>Path</th><th>State</th><th>Cause</th><th>Detail</th></tr></thead><tbody>\n");
        for inc in &pack.incidents {
            let _ = writeln!(
                s,
                "<tr><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{:.0}</td><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_esc(&inc.start_utc),
                html_esc(&inc.start_local),
                inc.duration_s,
                html_esc(&inc.iface),
                html_esc(&inc.state),
                html_esc(&inc.cause),
                html_esc(&inc.detail),
            );
        }
        s.push_str("</tbody></table>\n");
    }

    if !pack.security_notes.is_empty() {
        let _ = writeln!(s, "<h2>{}</h2><ul>", html_esc(h.security));
        for n in &pack.security_notes {
            let _ = writeln!(s, "<li>{}</li>", html_esc(n));
        }
        s.push_str("</ul>\n");
    }

    if !pack.free_text_notes.is_empty() {
        let _ = writeln!(s, "<h2>{}</h2><ul>", html_esc(h.free_notes));
        for n in &pack.free_text_notes {
            let _ = writeln!(s, "<li>{}</li>", html_esc(n));
        }
        s.push_str("</ul>\n");
    }

    s.push_str("</body>\n</html>\n");
    s
}

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\n', '\r'], " ")
}

fn html_esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}
