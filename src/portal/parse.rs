use std::collections::BTreeMap;

use scraper::{ElementRef, Html, Selector};
use serde::{Deserialize, Serialize};

use crate::error::GradeError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GradeRecord {
    pub fields: BTreeMap<String, String>,
}

impl GradeRecord {
    pub fn new(fields: BTreeMap<String, String>) -> Self {
        Self { fields }
    }

    pub fn get(&self, key: &str) -> &str {
        self.fields.get(key).map_or("", String::as_str)
    }

    pub fn nummer(&self) -> &str {
        self.get("Nummer")
    }

    pub fn titel(&self) -> &str {
        self.get("Titel")
    }
}

type Cell = (String, usize);

pub fn has_grades(html: &str) -> bool {
    html.contains("treeTableWithIcons") && html.contains("Bewertung")
}

pub fn parse_html_grades(html: &str) -> Result<Vec<GradeRecord>, GradeError> {
    let document = Html::parse_document(html);
    let table_selector = Selector::parse("table.treeTableWithIcons")
        .map_err(|e| GradeError::Parse(format!("invalid table selector: {e}")))?;

    for table in document.select(&table_selector) {
        let rows = direct_rows(table);
        let Some(header) = rows.first() else {
            continue;
        };
        if !normalized_text(header).contains("Bewertung") {
            continue;
        }

        let raw_header = direct_cells(*header);
        let body_rows = rows.iter().skip(1).copied().collect::<Vec<_>>();
        let raw_body = body_rows
            .iter()
            .copied()
            .map(direct_cells)
            .collect::<Vec<_>>();
        let mut records = parse_grades(&raw_header, &raw_body);
        for (record, row) in records.iter_mut().zip(body_rows) {
            if let Some(kind) = row_kind(row) {
                record.fields.insert("_row_kind".into(), kind);
            }
        }
        if records.is_empty() {
            return Err(GradeError::Parse(
                "grades table contained no body rows".into(),
            ));
        }
        return Ok(records);
    }

    Err(GradeError::Parse(
        "could not find treeTableWithIcons table with Bewertung header".into(),
    ))
}

fn direct_rows(table: ElementRef<'_>) -> Vec<ElementRef<'_>> {
    let mut rows = Vec::new();
    for child in table.children().filter_map(ElementRef::wrap) {
        match child.value().name() {
            "tr" => rows.push(child),
            "tbody" | "thead" => {
                rows.extend(
                    child
                        .children()
                        .filter_map(ElementRef::wrap)
                        .filter(|el| el.value().name() == "tr"),
                );
            }
            _ => {}
        }
    }
    rows
}

fn direct_cells(row: ElementRef<'_>) -> Vec<Cell> {
    row.children()
        .filter_map(ElementRef::wrap)
        .filter(|el| matches!(el.value().name(), "td" | "th"))
        .map(|cell| {
            let span = cell
                .value()
                .attr("colspan")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1)
                .max(1);
            (normalized_text(&cell), span)
        })
        .collect()
}

fn normalized_text(element: &ElementRef<'_>) -> String {
    element
        .text()
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn row_kind(row: ElementRef<'_>) -> Option<String> {
    let selector = Selector::parse("img[alt], img[title]").ok()?;
    row.select(&selector).find_map(|element| {
        element
            .value()
            .attr("alt")
            .or_else(|| element.value().attr("title"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

pub fn expand_spans(cells: &[Cell]) -> Vec<String> {
    let mut out = Vec::new();
    for (text, span) in cells {
        out.push(text.clone());
        out.extend(std::iter::repeat_n(String::new(), span.saturating_sub(1)));
    }
    out
}

pub fn parse_grades(header: &[Cell], body: &[Vec<Cell>]) -> Vec<GradeRecord> {
    let data_labels = header
        .iter()
        .skip(2)
        .map(|(text, _)| text.clone())
        .collect::<Vec<_>>();
    let n_data = data_labels.len();

    body.iter()
        .map(|cells| {
            let cols = expand_spans(cells);
            let mut fields = BTreeMap::new();
            if cols.len() <= n_data {
                fields.insert(
                    "Ebene".to_string(),
                    cols.first().cloned().unwrap_or_default(),
                );
                fields.insert(
                    "Titel".to_string(),
                    cols.iter()
                        .skip(1)
                        .filter(|c| !c.is_empty())
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" "),
                );
                return GradeRecord::new(fields);
            }

            let data_start = cols.len() - n_data;
            fields.insert("Ebene".to_string(), cols[0].clone());
            fields.insert(
                "Titel".to_string(),
                cols[1..data_start]
                    .iter()
                    .filter(|c| !c.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" "),
            );

            for (label, value) in data_labels.iter().zip(cols[data_start..].iter()) {
                fields.insert(label.clone(), value.clone());
            }
            GradeRecord::new(fields)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn right_aligns_data_block_after_colspan_expansion() {
        let header = vec![
            ("Ebene".into(), 1),
            ("Titel".into(), 1),
            ("Nummer".into(), 1),
            ("Bewertung".into(), 1),
            ("Status".into(), 1),
            ("Aktionen".into(), 1),
        ];
        let body = vec![vec![
            ("1.1.1.2".into(), 1),
            ("".into(), 1),
            ("Algorithms".into(), 2),
            ("CS101".into(), 1),
            ("1,7".into(), 1),
            ("bestanden".into(), 1),
            ("".into(), 1),
        ]];

        let records = parse_grades(&header, &body);
        assert_eq!(records[0].get("Ebene"), "1.1.1.2");
        assert_eq!(records[0].get("Titel"), "Algorithms");
        assert_eq!(records[0].get("Nummer"), "CS101");
        assert_eq!(records[0].get("Bewertung"), "1,7");
        assert_eq!(records[0].get("Status"), "bestanden");
    }

    #[test]
    fn parses_fixture_table() {
        let records = parse_html_grades(include_str!("../../tests/fixtures/meine_leistungen.html"))
            .expect("fixture parses");
        assert_eq!(records.len(), 4);
        assert_eq!(records[2].get("Ebene"), "1.1.1.2");
        assert_eq!(records[2].get("Titel"), "Datenbanken");
        assert_eq!(records[2].get("Nummer"), "IS-201");
        assert_eq!(records[2].get("Bewertung"), "1,7");
    }
}
