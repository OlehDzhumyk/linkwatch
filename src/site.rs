//! Optional site model: where the observation points are.
//!
//! Nothing is hard-coded. A TOML file defines reusable unit types (a flat, an office)
//! in metres with rooms (rectangles or polygons), walls, doors, named points and fixed
//! areas that are not tested (bathrooms, stairs). Buildings list their units by type
//! and floor. Coordinates: x to the right, y downwards, origin at the top-left corner of
//! the unit.
//!
//! Point ids are `<building>/<unit>/<point>`, e.g. `B1/F2/R3`. A room id is also a point
//! at the room centroid. Extra points (`[[point]]`) use full ids and unit coordinates.
//!
//! ```toml
//! [[unit_type]]
//! id = "flat"
//! width_m = 10.0
//! depth_m = 8.0
//! rooms = [{ id = "R1", name = "Bedroom", rect = [0, 0, 4, 4] }]
//! walls = [{ from = [0, 0], to = [10, 0], material = "concrete" }]
//! doors = [{ from = [0, 3.5], to = [0, 4.4], swing = "left", kind = "exit" }]
//! points = [{ id = "router", at = [9.5, 7.5], kind = "router" }]
//! fixed = [{ name = "Bathroom", rect = [8, 0, 2, 3] }]
//!
//! [[building]]
//! id = "B1"
//! units = [{ id = "F1", type = "flat", floor = 0 }, { id = "F2", type = "flat", floor = 0 }]
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

/// Gap between automatically placed units on one floor (metres).
const UNIT_GAP_M: f64 = 2.0;
/// Tolerance for "inside the unit" checks (metres).
const EPS: f64 = 1e-6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "lowercase")]
pub enum PointKind {
    Router,
    Ap,
    Booster,
    Probe,
    #[default]
    Other,
    /// Centroid of a room (generated, but also accepted in the file).
    Room,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteFile {
    #[serde(default)]
    unit_type: Vec<UnitType>,
    #[serde(default)]
    building: Vec<Building>,
    #[serde(default)]
    point: Vec<ExtraPoint>,
    #[serde(default)]
    plan: Vec<PlanDef>,
}

/// One `[[plan]]` entry: how long to measure at a point.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanDef {
    point: String,
    hours: f64,
    #[serde(default)]
    note: Option<String>,
}

/// Longest measurement planned at one point (one week).
pub const PLAN_MAX_HOURS: f64 = 168.0;

/// A validated plan entry.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanEntry {
    pub point: String,
    pub hours: f64,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "lowercase")]
pub enum WallMaterial {
    Concrete,
    Brick,
    #[default]
    Drywall,
    Glass,
    Wood,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "lowercase")]
pub enum DoorKind {
    #[default]
    Interior,
    Exit,
    Fire,
    Balcony,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "lowercase")]
pub enum DoorSwing {
    #[default]
    Left,
    Right,
    Double,
    Sliding,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WallDef {
    from: [f64; 2],
    to: [f64; 2],
    #[serde(default)]
    material: WallMaterial,
    #[serde(default)]
    thickness_cm: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DoorDef {
    from: [f64; 2],
    to: [f64; 2],
    #[serde(default)]
    swing: DoorSwing,
    #[serde(default)]
    kind: DoorKind,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitType {
    id: String,
    /// Accepted in the TOML for people reading the file; not used by the code.
    #[allow(dead_code)]
    name: Option<String>,
    width_m: f64,
    depth_m: f64,
    #[serde(default)]
    rooms: Vec<Area>,
    #[serde(default)]
    points: Vec<PointDef>,
    #[serde(default)]
    fixed: Vec<Area>,
    #[serde(default)]
    walls: Vec<WallDef>,
    #[serde(default)]
    doors: Vec<DoorDef>,
}

/// A room (with `id`) or a fixed area (with `name` only).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Area {
    id: Option<String>,
    name: Option<String>,
    rect: Option<[f64; 4]>,
    poly: Option<Vec<[f64; 2]>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PointDef {
    id: String,
    name: Option<String>,
    at: [f64; 2],
    #[serde(default)]
    kind: PointKind,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    bssids: Vec<String>,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Building {
    id: String,
    name: Option<String>,
    address: Option<String>,
    #[serde(default)]
    units: Vec<Unit>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Unit {
    id: String,
    #[serde(rename = "type")]
    type_id: String,
    floor: i32,
    label: Option<String>,
    /// Position of the unit's top-left corner on the floor plan. Default: units of a floor
    /// are placed left to right in file order with a 2 m gap.
    at: Option<[f64; 2]>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtraPoint {
    /// Full id `<building>/<unit>/<point>`.
    id: String,
    name: Option<String>,
    /// Unit coordinates in metres.
    at: [f64; 2],
    #[serde(default)]
    kind: PointKind,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    bssids: Vec<String>,
    #[serde(default)]
    notes: Option<String>,
}

/// A point with its position resolved.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResolvedPoint {
    /// `<building>/<unit>/<point>`.
    pub id: String,
    pub building: String,
    pub unit: String,
    pub point: String,
    pub name: String,
    pub kind: PointKind,
    pub floor: i32,
    /// Floor-plan coordinates in metres, mirrors applied.
    pub x: f64,
    pub y: f64,
    /// Room that contains the point (full id), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bssids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone)]
struct ResolvedArea {
    id: Option<String>,
    full_id: Option<String>,
    name: String,
    poly: Vec<[f64; 2]>,
    centroid: [f64; 2],
}

#[derive(Debug, Clone)]
struct ResolvedUnit {
    building: String,
    id: String,
    label: String,
    type_id: String,
    floor: i32,
    origin: [f64; 2],
    size: [f64; 2],
    rooms: Vec<ResolvedArea>,
    fixed: Vec<ResolvedArea>,
    walls: Vec<WallView>,
    doors: Vec<DoorView>,
    points: Vec<String>,
}

/// A validated site with resolved geometry.
#[derive(Debug, Clone)]
pub struct Site {
    file: SiteFile,
    units: Vec<ResolvedUnit>,
    points: BTreeMap<String, ResolvedPoint>,
    plan: Vec<PlanEntry>,
}

impl Site {
    /// Reads and validates a site TOML file.
    pub fn load(path: &Path) -> anyhow::Result<Site> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read site file {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| anyhow::anyhow!("site file {}: {e}", path.display()))
    }

    /// Parses and validates site TOML text.
    pub fn parse(text: &str) -> anyhow::Result<Site> {
        let file: SiteFile =
            toml::from_str(text).map_err(|e| anyhow::anyhow!("invalid TOML: {e}"))?;
        resolve(file)
    }

    /// Point by full id (`B1/F2/R3`); room ids resolve to the room centroid.
    pub fn point(&self, id: &str) -> Option<ResolvedPoint> {
        self.points.get(id).cloned()
    }

    /// The measurement plan (`[[plan]]`), in file order.
    pub fn plan(&self) -> &[PlanEntry] {
        &self.plan
    }

    /// Display name of a building (its id when it has no name).
    pub fn building_name(&self, id: &str) -> Option<&str> {
        self.file.building.iter().find(|b| b.id == id).map(|b| b.name.as_deref().unwrap_or(&b.id))
    }

    /// Label of a unit (its id when it has no label).
    pub fn unit_label(&self, building: &str, unit: &str) -> Option<&str> {
        self.units.iter().find(|u| u.building == building && u.id == unit).map(|u| u.label.as_str())
    }

    /// All points, sorted by id.
    #[cfg(test)]
    pub fn points(&self) -> impl Iterator<Item = &ResolvedPoint> {
        self.points.values()
    }

    /// Resolved geometry for the UI: buildings, each with floors (ascending), each with
    /// units placed on the floor plan; all coordinates in metres.
    pub fn view(&self) -> Vec<BuildingView<'_>> {
        let mut buildings = Vec::new();
        for b in &self.file.building {
            let mut floors: BTreeMap<i32, Vec<&ResolvedUnit>> = BTreeMap::new();
            for u in self.units.iter().filter(|u| u.building == b.id) {
                floors.entry(u.floor).or_default().push(u);
            }
            let floors = floors
                .into_iter()
                .map(|(floor, units)| FloorView {
                    floor,
                    width_m: units.iter().map(|u| u.origin[0] + u.size[0]).fold(0.0, f64::max),
                    depth_m: units.iter().map(|u| u.origin[1] + u.size[1]).fold(0.0, f64::max),
                    units: units.iter().map(|u| self.unit_view(u)).collect(),
                })
                .collect();
            buildings.push(BuildingView {
                id: &b.id,
                name: b.name.as_deref().unwrap_or(&b.id),
                address: b.address.as_deref(),
                floors,
            });
        }
        buildings
    }

    /// [`Site::view`] as JSON (`{"buildings": [...]}`), for tests.
    #[cfg(test)]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "buildings": self.view() })
    }

    fn unit_view<'a>(&'a self, u: &'a ResolvedUnit) -> UnitView<'a> {
        let neighbors = |room: &ResolvedArea, target_floor: i32| -> Vec<VerticalNeighbor> {
            let mut out = Vec::new();
            for u2 in self.units.iter().filter(|x| x.building == u.building && x.floor == target_floor) {
                let unit_full = format!("{}/{}", u2.building, u2.id);
                for r2 in &u2.rooms {
                    let Some(full) = &r2.full_id else { continue };
                    if polys_overlap(&room.poly, room.centroid, &r2.poly, r2.centroid) {
                        out.push(VerticalNeighbor {
                            point: full.clone(),
                            name: r2.name.clone(),
                            unit: unit_full.clone(),
                            unit_label: u2.label.clone(),
                            floor: u2.floor,
                            kind: PointKind::Room,
                        });
                    }
                }
                for pid in &u2.points {
                    let Some(p2) = self.points.get(pid) else { continue };
                    if p2.kind != PointKind::Room && contains(&room.poly, [p2.x, p2.y]) {
                        out.push(VerticalNeighbor {
                            point: p2.id.clone(),
                            name: p2.name.clone(),
                            unit: unit_full.clone(),
                            unit_label: u2.label.clone(),
                            floor: u2.floor,
                            kind: p2.kind,
                        });
                    }
                }
            }
            out
        };
        let room_area = |a: &'a ResolvedArea| AreaView {
            id: a.id.as_deref(),
            full_id: a.full_id.as_deref(),
            name: &a.name,
            poly: &a.poly,
            centroid: a.centroid,
            above: neighbors(a, u.floor + 1),
            below: neighbors(a, u.floor - 1),
            rf: a.full_id.as_deref().and_then(|id| self.estimate_rf(id)),
        };
        let fixed_area = |a: &'a ResolvedArea| AreaView {
            id: a.id.as_deref(),
            full_id: a.full_id.as_deref(),
            name: &a.name,
            poly: &a.poly,
            centroid: a.centroid,
            above: Vec::new(),
            below: Vec::new(),
            rf: None,
        };
        let points = u
            .points
            .iter()
            .filter_map(|id| self.points.get(id))
            .filter(|p| p.kind != PointKind::Room)
            .map(|p| PointView {
                id: &p.point,
                full_id: &p.id,
                name: &p.name,
                kind: p.kind,
                at: [p.x, p.y],
                mac: p.mac.as_deref(),
                bssids: &p.bssids,
                notes: p.notes.as_deref(),
            })
            .collect();
        UnitView {
            id: &u.id,
            full_id: format!("{}/{}", u.building, u.id),
            label: &u.label,
            type_id: &u.type_id,
            x: u.origin[0],
            y: u.origin[1],
            width_m: u.size[0],
            depth_m: u.size[1],
            rooms: u.rooms.iter().map(room_area).collect(),
            fixed: u.fixed.iter().map(fixed_area).collect(),
            walls: &u.walls,
            doors: &u.doors,
            points,
        }
    }
}

/// A room or device point directly above or below a room on an adjacent floor.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct VerticalNeighbor {
    pub point: String,
    pub name: String,
    pub unit: String,
    pub unit_label: String,
    pub floor: i32,
    pub kind: PointKind,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct WallView {
    pub from: [f64; 2],
    pub to: [f64; 2],
    pub material: WallMaterial,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thickness_cm: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct DoorView {
    pub from: [f64; 2],
    pub to: [f64; 2],
    pub swing: DoorSwing,
    pub kind: DoorKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// One building of [`Site::view`] (JSON for the web UI).
#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct BuildingView<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub address: Option<&'a str>,
    /// Ascending by floor number.
    pub floors: Vec<FloorView<'a>>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct FloorView<'a> {
    pub floor: i32,
    /// Extent of the floor plan (all units), metres.
    pub width_m: f64,
    pub depth_m: f64,
    pub units: Vec<UnitView<'a>>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct UnitView<'a> {
    pub id: &'a str,
    pub full_id: String,
    pub label: &'a str,
    #[serde(rename = "type")]
    pub type_id: &'a str,
    /// Top-left corner on the floor plan, metres.
    pub x: f64,
    pub y: f64,
    pub width_m: f64,
    pub depth_m: f64,
    pub rooms: Vec<AreaView<'a>>,
    pub fixed: Vec<AreaView<'a>>,
    pub walls: &'a [WallView],
    pub doors: &'a [DoorView],
    pub points: Vec<PointView<'a>>,
}

/// RF obstacle attenuation estimate from the nearest router/AP in the same building.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct RfPathEstimate {
    pub router_point: String,
    pub distance_m: f64,
    pub walls_crossed: u32,
    pub floors_crossed: u32,
    pub obstacle_loss_db: f64,
}

/// Approximate 5 GHz attenuation (dB) of one wall by material and optional thickness.
pub fn wall_attenuation_db(m: WallMaterial, thickness_cm: Option<f64>) -> f64 {
    let (base, typ_cm) = match m {
        WallMaterial::Glass => (2.5, 2.0),
        WallMaterial::Drywall => (3.0, 10.0),
        WallMaterial::Wood => (4.0, 5.0),
        WallMaterial::Brick => (9.0, 15.0),
        WallMaterial::Concrete => (14.0, 20.0),
    };
    match thickness_cm {
        Some(t) if t > typ_cm => base * (t / typ_cm).min(2.0),
        _ => base,
    }
}

fn orient(a: [f64; 2], b: [f64; 2], c: [f64; 2]) -> f64 {
    (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])
}

fn on_seg(a: [f64; 2], b: [f64; 2], c: [f64; 2]) -> bool {
    c[0] >= a[0].min(b[0]) - EPS
        && c[0] <= a[0].max(b[0]) + EPS
        && c[1] >= a[1].min(b[1]) - EPS
        && c[1] <= a[1].max(b[1]) + EPS
}

fn segments_intersect(a1: [f64; 2], a2: [f64; 2], b1: [f64; 2], b2: [f64; 2]) -> bool {
    if a1[0].max(a2[0]) < b1[0].min(b2[0]) - EPS
        || b1[0].max(b2[0]) < a1[0].min(a2[0]) - EPS
        || a1[1].max(a2[1]) < b1[1].min(b2[1]) - EPS
        || b1[1].max(b2[1]) < a1[1].min(a2[1]) - EPS
    {
        return false;
    }
    let d1 = orient(b1, b2, a1);
    let d2 = orient(b1, b2, a2);
    let d3 = orient(a1, a2, b1);
    let d4 = orient(a1, a2, b2);
    if ((d1 > EPS && d2 < -EPS) || (d1 < -EPS && d2 > EPS))
        && ((d3 > EPS && d4 < -EPS) || (d3 < -EPS && d4 > EPS))
    {
        return true;
    }
    (d1.abs() <= EPS && on_seg(b1, b2, a1))
        || (d2.abs() <= EPS && on_seg(b1, b2, a2))
        || (d3.abs() <= EPS && on_seg(a1, a2, b1))
        || (d4.abs() <= EPS && on_seg(a1, a2, b2))
}

impl Site {
    /// Estimates 5 GHz obstacle attenuation from the nearest Router/AP point in the same building.
    pub fn estimate_rf(&self, target_point_id: &str) -> Option<RfPathEstimate> {
        let tp = self.points.get(target_point_id)?;
        let rp = self
            .points
            .values()
            .filter(|p| {
                p.building == tp.building
                    && matches!(p.kind, PointKind::Router | PointKind::Ap)
                    && p.id != tp.id
            })
            .min_by(|a, b| {
                let ka = (a.unit != tp.unit, (a.floor - tp.floor).unsigned_abs(), (a.x - tp.x).hypot(a.y - tp.y));
                let kb = (b.unit != tp.unit, (b.floor - tp.floor).unsigned_abs(), (b.x - tp.x).hypot(b.y - tp.y));
                (ka.0, ka.1).cmp(&(kb.0, kb.1)).then_with(|| ka.2.total_cmp(&kb.2))
            })?;

        let floors_crossed = (rp.floor - tp.floor).unsigned_abs();
        let planar_m = (tp.x - rp.x).hypot(tp.y - rp.y);
        let distance_m = ((planar_m.hypot(f64::from(floors_crossed) * 3.0)) * 10.0).round() / 10.0;

        let mut walls_crossed = 0u32;
        let mut loss_db = f64::from(floors_crossed) * 15.0;
        let src = [rp.x, rp.y];
        let dst = [tp.x, tp.y];
        for u in self.units.iter().filter(|u| u.building == tp.building && u.floor == tp.floor) {
            if floors_crossed > 0 && u.id != tp.unit {
                continue;
            }
            for w in &u.walls {
                // Skip exact endpoint touches (e.g. a wall segment starting at the router marker).
                let near_src = (w.from[0] - src[0]).hypot(w.from[1] - src[1]) < 0.05
                    || (w.to[0] - src[0]).hypot(w.to[1] - src[1]) < 0.05;
                let near_dst = (w.from[0] - dst[0]).hypot(w.from[1] - dst[1]) < 0.05
                    || (w.to[0] - dst[0]).hypot(w.to[1] - dst[1]) < 0.05;
                if !near_src && !near_dst && segments_intersect(src, dst, w.from, w.to) {
                    walls_crossed += 1;
                    loss_db += wall_attenuation_db(w.material, w.thickness_cm);
                }
            }
        }

        Some(RfPathEstimate {
            router_point: rp.id.clone(),
            distance_m,
            walls_crossed,
            floors_crossed,
            obstacle_loss_db: (loss_db * 10.0).round() / 10.0,
        })
    }
}

/// A room (with ids) or a fixed area (without ids), floor-plan coordinates in metres.
#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct AreaView<'a> {
    pub id: Option<&'a str>,
    pub full_id: Option<&'a str>,
    pub name: &'a str,
    pub poly: &'a [[f64; 2]],
    pub centroid: [f64; 2],
    pub above: Vec<VerticalNeighbor>,
    pub below: Vec<VerticalNeighbor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(test, ts(optional))]
    pub rf: Option<RfPathEstimate>,
}

/// A named point (not a room centroid), floor-plan coordinates in metres.
#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, optional_fields))]
pub struct PointView<'a> {
    pub id: &'a str,
    pub full_id: &'a str,
    pub name: &'a str,
    pub kind: PointKind,
    pub at: [f64; 2],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<&'a str>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    #[cfg_attr(test, ts(optional = nullable))]
    pub bssids: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<&'a str>,
}

fn check_id(what: &str, id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !id.is_empty() && !id.contains('/') && !id.chars().any(char::is_whitespace),
        "{what}: id {id:?} must be non-empty without '/' or spaces"
    );
    Ok(())
}

fn normalize_mac(what: &str, raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    let sep = if trimmed.contains(':') { ':' } else { '-' };
    let parts: Vec<&str> = trimmed.split(sep).collect();
    anyhow::ensure!(
        parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit())),
        "{what}: invalid MAC/BSSID {raw:?} (expected 6 hex bytes like 02:00:00:00:00:01)"
    );
    Ok(parts.join(":").to_ascii_lowercase())
}

fn normalize_point_macs(
    what: &str,
    mac: Option<&str>,
    bssids: &[String],
) -> anyhow::Result<(Option<String>, Vec<String>)> {
    let mac = mac.map(|m| normalize_mac(what, m)).transpose()?;
    let mut norm_bssids = Vec::with_capacity(bssids.len());
    for b in bssids {
        let nb = normalize_mac(what, b)?;
        if !norm_bssids.contains(&nb) {
            norm_bssids.push(nb);
        }
    }
    Ok((mac, norm_bssids))
}

fn finite(what: &str, vals: &[f64]) -> anyhow::Result<()> {
    anyhow::ensure!(
        vals.iter().all(|v| v.is_finite()),
        "{what}: coordinates must be finite numbers"
    );
    Ok(())
}

fn inside(p: [f64; 2], w: f64, d: f64) -> bool {
    p[0] >= -EPS && p[1] >= -EPS && p[0] <= w + EPS && p[1] <= d + EPS
}

/// Polygon of an area in unit coordinates, validated against the unit bounds.
fn area_poly(what: &str, a: &Area, w: f64, d: f64) -> anyhow::Result<Vec<[f64; 2]>> {
    let poly = match (&a.rect, &a.poly) {
        (Some(r), None) => {
            finite(what, r)?;
            let [x, y, rw, rh] = *r;
            anyhow::ensure!(
                rw > 0.0 && rh > 0.0,
                "{what}: rect {r:?} needs positive width and height"
            );
            anyhow::ensure!(
                inside([x, y], w, d) && inside([x + rw, y + rh], w, d),
                "{what}: rect {r:?} goes outside the unit (0..{w} x 0..{d} m)"
            );
            vec![[x, y], [x + rw, y], [x + rw, y + rh], [x, y + rh]]
        }
        (None, Some(p)) => {
            anyhow::ensure!(p.len() >= 3, "{what}: poly needs at least 3 points");
            for v in p {
                finite(what, v)?;
                anyhow::ensure!(
                    inside(*v, w, d),
                    "{what}: poly point {v:?} is outside the unit (0..{w} x 0..{d} m)"
                );
            }
            anyhow::ensure!(polygon_area(p).abs() > EPS, "{what}: poly has zero area");
            p.clone()
        }
        (Some(_), Some(_)) => anyhow::bail!("{what}: give either rect or poly, not both"),
        (None, None) => anyhow::bail!("{what}: needs rect = [x, y, w, h] or poly = [[x, y], ...]"),
    };
    Ok(poly)
}

fn polygon_area(p: &[[f64; 2]]) -> f64 {
    let n = p.len();
    (0..n)
        .map(|i| p[i][0] * p[(i + 1) % n][1] - p[(i + 1) % n][0] * p[i][1])
        .sum::<f64>()
        / 2.0
}

fn centroid(p: &[[f64; 2]]) -> [f64; 2] {
    let a = polygon_area(p);
    let n = p.len();
    if a.abs() < EPS || n == 0 {
        let k = n.max(1) as f64;
        return [
            p.iter().map(|v| v[0]).sum::<f64>() / k,
            p.iter().map(|v| v[1]).sum::<f64>() / k,
        ];
    }
    let (mut cx, mut cy) = (0.0, 0.0);
    for i in 0..n {
        let (a0, a1) = (p[i], p[(i + 1) % n]);
        let cross = a0[0] * a1[1] - a1[0] * a0[1];
        cx += (a0[0] + a1[0]) * cross;
        cy += (a0[1] + a1[1]) * cross;
    }
    [cx / (6.0 * a), cy / (6.0 * a)]
}

fn contains(poly: &[[f64; 2]], p: [f64; 2]) -> bool {
    let mut inside = false;
    let n = poly.len();
    let mut j = n.wrapping_sub(1);
    for i in 0..n {
        let (a, b) = (poly[i], poly[j]);
        if (a[1] > p[1]) != (b[1] > p[1])
            && p[0] < (b[0] - a[0]) * (p[1] - a[1]) / (b[1] - a[1]) + a[0]
        {
            inside = !inside;
        }
        j = i;
    }
    inside
}

fn bbox(poly: &[[f64; 2]]) -> (f64, f64, f64, f64) {
    let mut x0 = f64::MAX;
    let mut x1 = f64::MIN;
    let mut y0 = f64::MAX;
    let mut y1 = f64::MIN;
    for &[x, y] in poly {
        x0 = x0.min(x);
        x1 = x1.max(x);
        y0 = y0.min(y);
        y1 = y1.max(y);
    }
    (x0, x1, y0, y1)
}

fn polys_overlap(a: &[[f64; 2]], ca: [f64; 2], b: &[[f64; 2]], cb: [f64; 2]) -> bool {
    let (ax0, ax1, ay0, ay1) = bbox(a);
    let (bx0, bx1, by0, by1) = bbox(b);
    let ix0 = ax0.max(bx0);
    let ix1 = ax1.min(bx1);
    let iy0 = ay0.max(by0);
    let iy1 = ay1.min(by1);
    if ix1 - ix0 <= 0.05 || iy1 - iy0 <= 0.05 {
        return false;
    }
    if contains(b, ca) || contains(a, cb) {
        return true;
    }
    for fx in [0.25, 0.5, 0.75] {
        for fy in [0.25, 0.5, 0.75] {
            let p = [ix0 + (ix1 - ix0) * fx, iy0 + (iy1 - iy0) * fy];
            if contains(a, p) && contains(b, p) {
                return true;
            }
        }
    }
    false
}

/// Validated geometry of a unit type, in unit coordinates.
struct TypeGeom<'a> {
    t: &'a UnitType,
    rooms: Vec<(String, String, Vec<[f64; 2]>)>,
    fixed: Vec<(String, Vec<[f64; 2]>)>,
}

fn validate_segment(what: &str, from: [f64; 2], to: [f64; 2], w: f64, d: f64) -> anyhow::Result<()> {
    finite(what, &from)?;
    finite(what, &to)?;
    anyhow::ensure!(
        inside(from, w, d) && inside(to, w, d),
        "{what}: segment {from:?}..{to:?} goes outside the unit (0..{w} x 0..{d} m)"
    );
    let len = (to[0] - from[0]).hypot(to[1] - from[1]);
    anyhow::ensure!(len > EPS, "{what}: segment has zero length");
    Ok(())
}

fn validate_type(t: &UnitType) -> anyhow::Result<TypeGeom<'_>> {
    check_id("unit_type", &t.id)?;
    let what = format!("unit_type {:?}", t.id);
    anyhow::ensure!(
        t.width_m.is_finite() && t.depth_m.is_finite() && t.width_m > 0.0 && t.depth_m > 0.0,
        "{what}: width_m and depth_m must be positive"
    );
    let (w, d) = (t.width_m, t.depth_m);
    let mut ids = HashSet::new();
    let mut rooms = Vec::new();
    for (i, r) in t.rooms.iter().enumerate() {
        let id =
            r.id.clone()
                .ok_or_else(|| anyhow::anyhow!("{what}: room #{} has no id", i + 1))?;
        let rw = format!("{what} room {id:?}");
        check_id(&rw, &id)?;
        anyhow::ensure!(
            ids.insert(id.clone()),
            "{rw}: id used twice in this unit type"
        );
        let poly = area_poly(&rw, r, w, d)?;
        rooms.push((id.clone(), r.name.clone().unwrap_or(id), poly));
    }
    for p in &t.points {
        let pw = format!("{what} point {:?}", p.id);
        check_id(&pw, &p.id)?;
        anyhow::ensure!(
            ids.insert(p.id.clone()),
            "{pw}: id already used by a room or point"
        );
        finite(&pw, &p.at)?;
        anyhow::ensure!(
            inside(p.at, w, d),
            "{pw}: at {:?} is outside the unit (0..{w} x 0..{d} m)",
            p.at
        );
        normalize_point_macs(&pw, p.mac.as_deref(), &p.bssids)?;
    }
    let mut fixed = Vec::new();
    for (i, f) in t.fixed.iter().enumerate() {
        let name = f
            .name
            .clone()
            .or_else(|| f.id.clone())
            .unwrap_or_else(|| format!("fixed #{}", i + 1));
        let fw = format!("{what} fixed area {name:?}");
        fixed.push((name, area_poly(&fw, f, w, d)?));
    }
    for (i, wall) in t.walls.iter().enumerate() {
        let ww = format!("{what} wall #{}", i + 1);
        validate_segment(&ww, wall.from, wall.to, w, d)?;
        if let Some(th) = wall.thickness_cm {
            anyhow::ensure!(
                th.is_finite() && th > 0.0 && th <= 200.0,
                "{ww}: thickness_cm must be between 0 and 200"
            );
        }
    }
    for (i, door) in t.doors.iter().enumerate() {
        let dw = format!("{what} door #{}", i + 1);
        validate_segment(&dw, door.from, door.to, w, d)?;
    }
    Ok(TypeGeom { t, rooms, fixed })
}

fn resolve(file: SiteFile) -> anyhow::Result<Site> {
    let mut types: HashMap<&str, TypeGeom<'_>> = HashMap::new();
    for t in &file.unit_type {
        let g = validate_type(t)?;
        anyhow::ensure!(
            types.insert(t.id.as_str(), g).is_none(),
            "unit_type {:?} is defined twice",
            t.id
        );
    }

    let mut units = Vec::new();
    let mut points: BTreeMap<String, ResolvedPoint> = BTreeMap::new();
    let mut building_ids = HashSet::new();
    // Next free x per (building, floor) for automatic placement.
    let mut next_x: HashMap<(String, i32), f64> = HashMap::new();
    for b in &file.building {
        check_id("building", &b.id)?;
        anyhow::ensure!(
            building_ids.insert(b.id.as_str()),
            "building {:?} is defined twice",
            b.id
        );
        let mut unit_ids = HashSet::new();
        for u in &b.units {
            let uw = format!("building {:?} unit {:?}", b.id, u.id);
            check_id(&uw, &u.id)?;
            anyhow::ensure!(
                unit_ids.insert(u.id.as_str()),
                "{uw}: unit id used twice in this building"
            );
            let g = types
                .get(u.type_id.as_str())
                .ok_or_else(|| anyhow::anyhow!("{uw}: unknown unit type {:?}", u.type_id))?;
            let (w, d) = (g.t.width_m, g.t.depth_m);
            let origin = match u.at {
                Some(a) => {
                    finite(&uw, &a)?;
                    a
                }
                None => {
                    let x = next_x.entry((b.id.clone(), u.floor)).or_insert(0.0);
                    let o = [*x, 0.0];
                    *x += w + UNIT_GAP_M;
                    o
                }
            };
            let tf = |p: [f64; 2]| -> [f64; 2] { [origin[0] + p[0], origin[1] + p[1]] };
            let prefix = format!("{}/{}", b.id, u.id);
            let rooms: Vec<ResolvedArea> = g
                .rooms
                .iter()
                .map(|(id, name, poly)| {
                    let poly: Vec<[f64; 2]> = poly.iter().map(|p| tf(*p)).collect();
                    let c = centroid(&poly);
                    ResolvedArea {
                        id: Some(id.clone()),
                        full_id: Some(format!("{prefix}/{id}")),
                        name: name.clone(),
                        poly,
                        centroid: c,
                    }
                })
                .collect();
            let fixed: Vec<ResolvedArea> = g
                .fixed
                .iter()
                .map(|(name, poly)| {
                    let poly: Vec<[f64; 2]> = poly.iter().map(|p| tf(*p)).collect();
                    let c = centroid(&poly);
                    ResolvedArea {
                        id: None,
                        full_id: None,
                        name: name.clone(),
                        poly,
                        centroid: c,
                    }
                })
                .collect();
            let room_of = |p: [f64; 2]| {
                rooms
                    .iter()
                    .find(|r| contains(&r.poly, p))
                    .and_then(|r| r.full_id.clone())
            };
            let mut ids = Vec::new();
            for r in &rooms {
                let (Some(id), Some(full)) = (&r.id, &r.full_id) else {
                    continue;
                };
                points.insert(
                    full.clone(),
                    ResolvedPoint {
                        id: full.clone(),
                        building: b.id.clone(),
                        unit: u.id.clone(),
                        point: id.clone(),
                        name: r.name.clone(),
                        kind: PointKind::Room,
                        floor: u.floor,
                        x: r.centroid[0],
                        y: r.centroid[1],
                        room: Some(full.clone()),
                        mac: None,
                        bssids: Vec::new(),
                        notes: None,
                    },
                );
                ids.push(full.clone());
            }
            for p in &g.t.points {
                let full = format!("{prefix}/{}", p.id);
                let pw = format!("unit_type {:?} point {:?}", g.t.id, p.id);
                let (mac, bssids) = normalize_point_macs(&pw, p.mac.as_deref(), &p.bssids)?;
                let at = tf(p.at);
                points.insert(
                    full.clone(),
                    ResolvedPoint {
                        id: full.clone(),
                        building: b.id.clone(),
                        unit: u.id.clone(),
                        point: p.id.clone(),
                        name: p.name.clone().unwrap_or_else(|| p.id.clone()),
                        kind: p.kind,
                        floor: u.floor,
                        x: at[0],
                        y: at[1],
                        room: room_of(at),
                        mac,
                        bssids,
                        notes: p.notes.clone(),
                    },
                );
                ids.push(full);
            }
            let walls = g
                .t
                .walls
                .iter()
                .map(|wall| WallView {
                    from: tf(wall.from),
                    to: tf(wall.to),
                    material: wall.material,
                    thickness_cm: wall.thickness_cm,
                })
                .collect();
            let doors = g
                .t
                .doors
                .iter()
                .map(|door| DoorView {
                    from: tf(door.from),
                    to: tf(door.to),
                    swing: door.swing,
                    kind: door.kind,
                    label: door.label.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string),
                })
                .collect();
            units.push(ResolvedUnit {
                building: b.id.clone(),
                id: u.id.clone(),
                label: u.label.clone().unwrap_or_else(|| u.id.clone()),
                type_id: u.type_id.clone(),
                floor: u.floor,
                origin,
                size: [w, d],
                rooms,
                fixed,
                walls,
                doors,
                points: ids,
            });
        }
    }

    for x in &file.point {
        let what = format!("point {:?}", x.id);
        let parts: Vec<&str> = x.id.split('/').collect();
        let [bid, uid, pid] = parts.as_slice() else {
            anyhow::bail!("{what}: id must be <building>/<unit>/<point>");
        };
        check_id(&what, pid)?;
        anyhow::ensure!(
            !points.contains_key(&x.id),
            "{what}: id already used by a room or point"
        );
        let u = units
            .iter_mut()
            .find(|u| u.building == *bid && u.id == *uid)
            .ok_or_else(|| anyhow::anyhow!("{what}: no unit {uid:?} in building {bid:?}"))?;
        finite(&what, &x.at)?;
        anyhow::ensure!(
            inside(x.at, u.size[0], u.size[1]),
            "{what}: at {:?} is outside the unit (0..{} x 0..{} m)",
            x.at,
            u.size[0],
            u.size[1]
        );
        let at = [u.origin[0] + x.at[0], u.origin[1] + x.at[1]];
        let room = u
            .rooms
            .iter()
            .find(|r| contains(&r.poly, at))
            .and_then(|r| r.full_id.clone());
        let (mac, bssids) = normalize_point_macs(&what, x.mac.as_deref(), &x.bssids)?;
        points.insert(
            x.id.clone(),
            ResolvedPoint {
                id: x.id.clone(),
                building: bid.to_string(),
                unit: uid.to_string(),
                point: pid.to_string(),
                name: x.name.clone().unwrap_or_else(|| pid.to_string()),
                kind: x.kind,
                floor: u.floor,
                x: at[0],
                y: at[1],
                room,
                mac,
                bssids,
                notes: x.notes.clone(),
            },
        );
        u.points.push(x.id.clone());
    }

    let mut plan = Vec::with_capacity(file.plan.len());
    let mut planned = HashSet::new();
    for (i, e) in file.plan.iter().enumerate() {
        let what = format!("plan #{} (point {:?})", i + 1, e.point);
        anyhow::ensure!(points.contains_key(&e.point), "{what}: no such point in this site");
        anyhow::ensure!(planned.insert(e.point.as_str()), "{what}: point is planned twice");
        anyhow::ensure!(
            e.hours.is_finite() && e.hours > 0.0 && e.hours <= PLAN_MAX_HOURS,
            "{what}: hours must be more than 0 and at most {PLAN_MAX_HOURS}"
        );
        let note = e.note.as_deref().map(str::trim).filter(|n| !n.is_empty());
        if let Some(n) = note {
            anyhow::ensure!(
                n.chars().count() <= 200 && !n.chars().any(char::is_control),
                "{what}: note must be at most 200 characters without control characters"
            );
        }
        plan.push(PlanEntry { point: e.point.clone(), hours: e.hours, note: note.map(str::to_string) });
    }

    Ok(Site {
        file,
        units,
        points,
        plan,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: &str = r#"
[[unit_type]]
id = "flat"
width_m = 10.0
depth_m = 8.0
rooms = [
  { id = "R1", name = "Bedroom", rect = [0, 0, 4, 4] },
  { id = "K", poly = [[4, 0], [10, 0], [10, 8], [4, 8]] },
]
walls = [
  { from = [0, 0], to = [10, 0], material = "concrete", thickness_cm = 25 },
  { from = [4, 0], to = [4, 8], material = "brick" },
]
doors = [
  { from = [0, 3], to = [0, 4], swing = "left", kind = "exit", label = "Exit" },
]
points = [{ id = "router", at = [9.5, 7.5], kind = "router" }]
fixed = [{ name = "Bath", rect = [0, 4, 4, 4] }]

[[building]]
id = "B1"
units = [
  { id = "F1", type = "flat", floor = 0 },
  { id = "F2", type = "flat", floor = 0 },
]

[[point]]
id = "B1/F2/desk"
at = [1, 1]
kind = "probe"
"#;

    fn err(text: &str) -> String {
        Site::parse(text).unwrap_err().to_string()
    }

    #[test]
    fn resolves_points_and_units() {
        let s = Site::parse(SMALL).unwrap();
        let r1 = s.point("B1/F1/R1").unwrap();
        assert_eq!((r1.x, r1.y, r1.kind), (2.0, 2.0, PointKind::Room));
        let router = s.point("B1/F1/router").unwrap();
        assert_eq!((router.x, router.y), (9.5, 7.5));
        assert_eq!(router.room.as_deref(), Some("B1/F1/K"));
        // F2 starts at 10 + 2 m gap with the same unit type coordinates.
        let r = s.point("B1/F2/router").unwrap();
        assert_eq!((r.x, r.y), (12.0 + 9.5, 7.5));
        let desk = s.point("B1/F2/desk").unwrap();
        assert_eq!((desk.x, desk.kind), (12.0 + 1.0, PointKind::Probe));
        assert_eq!(desk.room, Some("B1/F2/R1".into()));
        assert!(s.point("B1/F3/R1").is_none());
        let k = s.point("B1/F1/K").unwrap();
        assert!((k.x - 7.0).abs() < 1e-9 && (k.y - 4.0).abs() < 1e-9);
    }

    #[test]
    fn json_groups_by_building_and_floor() {
        let j = Site::parse(SMALL).unwrap().to_json();
        let f = &j["buildings"][0]["floors"][0];
        assert_eq!(f["floor"], 0);
        assert_eq!(f["width_m"], 22.0);
        assert_eq!(f["units"].as_array().unwrap().len(), 2);
        let poly = f["units"][1]["rooms"][0]["poly"].as_array().unwrap();
        let xs: Vec<f64> = poly.iter().map(|p| p[0].as_f64().unwrap()).collect();
        assert_eq!(xs.iter().cloned().fold(f64::MAX, f64::min), 12.0);
        assert_eq!(f["units"][1]["points"].as_array().unwrap().len(), 2);
        assert_eq!(f["units"][0]["fixed"][0]["name"], "Bath");
        assert_eq!(f["units"][0]["walls"].as_array().unwrap().len(), 2);
        assert_eq!(f["units"][0]["doors"][0]["kind"], "exit");
    }

    #[test]
    fn validation_names_the_item() {
        let base = SMALL.split("[[point]]").next().unwrap();
        let e = err(&base.replace("rect = [0, 0, 4, 4]", "rect = [8, 0, 4, 4]"));
        assert!(e.contains("room \"R1\"") && e.contains("outside"), "{e}");
        let e = err(&base.replace("at = [9.5, 7.5]", "at = [11, 7.5]"));
        assert!(e.contains("point \"router\""), "{e}");
        let e = err(&base.replace("to = [10, 0]", "to = [12, 0]"));
        assert!(e.contains("wall #1") && e.contains("outside"), "{e}");
        let e = err(&base.replace("to = [0, 4]", "to = [0, 3]"));
        assert!(e.contains("door #1") && e.contains("zero length"), "{e}");
        let e = err(&base.replace(
            "type = \"flat\", floor = 0 }",
            "type = \"nope\", floor = 0 }",
        ));
        assert!(
            e.contains("unit \"F1\"") && e.contains("unknown unit type"),
            "{e}"
        );
        let e = err(&base.replace("id = \"F2\"", "id = \"F1\""));
        assert!(e.contains("used twice"), "{e}");
        let e = err(&base.replace("id = \"router\"", "id = \"R1\""));
        assert!(e.contains("already used"), "{e}");
        let e = err(&format!(
            "{base}\n[[point]]\nid = \"B1/F9/x\"\nat = [1, 1]\n"
        ));
        assert!(e.contains("no unit \"F9\""), "{e}");
        let e = err(&format!(
            "{base}\n[[point]]\nid = \"B1/F1/R1\"\nat = [1, 1]\n"
        ));
        assert!(e.contains("already used"), "{e}");
        let e = err(&base.replace(
            "{ name = \"Bath\", rect = [0, 4, 4, 4] }",
            "{ name = \"Bath\" }",
        ));
        assert!(e.contains("fixed area \"Bath\""), "{e}");
        let e = err(&format!(
            "{base}\n[[unit_type]]\nid = \"flat\"\nwidth_m = 1.0\ndepth_m = 1.0\n"
        ));
        assert!(e.contains("defined twice"), "{e}");
    }

    #[test]
    fn example_site_file_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/site.toml");
        let s = Site::load(&path).unwrap();
        let b1 = s.point("B1/F1/router").unwrap();
        let b2 = s.point("B1/F2/router").unwrap();
        assert_eq!(b1.room.as_deref(), Some("B1/F1/K"));
        assert_eq!(b2.room.as_deref(), Some("B1/F2/K"));
        assert!(b2.x - 12.0 < 1.0, "{}", b2.x);
        assert_eq!(s.point("B2/F4/R3").unwrap().floor, 1);
        assert_eq!(
            s.points().filter(|p| p.kind == PointKind::Room).count(),
            2 * 4 * 5
        );
        let j = s.to_json();
        assert_eq!(j["buildings"].as_array().unwrap().len(), 2);
        assert_eq!(j["buildings"][1]["floors"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn walls_doors_and_vertical_neighbors() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/site.toml");
        let s = Site::load(&path).unwrap();
        let j = s.to_json();
        let f1_ground = &j["buildings"][0]["floors"][0]["units"][0];
        let f3_above = &j["buildings"][0]["floors"][1]["units"][0];
        let r1 = f1_ground["rooms"].as_array().unwrap().iter().find(|r| r["id"] == "R1").unwrap();
        let above = r1["above"].as_array().unwrap();
        assert!(above.iter().any(|n| n["point"] == "B1/F3/R1" && n["kind"] == "room"), "{above:?}");
        assert!(r1["below"].as_array().unwrap().is_empty());

        let k_above = f3_above["rooms"].as_array().unwrap().iter().find(|r| r["id"] == "K").unwrap();
        let below = k_above["below"].as_array().unwrap();
        assert!(below.iter().any(|n| n["point"] == "B1/F1/K" && n["kind"] == "room"), "{below:?}");
        assert!(below.iter().any(|n| n["point"] == "B1/F1/router" && n["kind"] == "router"), "{below:?}");
    }

    #[test]
    fn plan_is_validated() {
        let base = SMALL.split("[[point]]").next().unwrap();
        let ok = format!("{base}\n[[plan]]\npoint = \"B1/F1/R1\"\nhours = 8\nnote = \" first night \"\n\n[[plan]]\npoint = \"B1/F2/K\"\nhours = 0.5\n");
        let s = Site::parse(&ok).unwrap();
        assert_eq!(s.plan().len(), 2);
        assert_eq!(s.plan()[0], PlanEntry { point: "B1/F1/R1".into(), hours: 8.0, note: Some("first night".into()) });
        assert_eq!(s.building_name("B1"), Some("B1"));
        assert_eq!(s.unit_label("B1", "F2"), Some("F2"));
        let plan = |p: &str, h: &str| format!("{base}\n[[plan]]\npoint = \"{p}\"\nhours = {h}\n");
        let e = err(&plan("B1/F9/R1", "8"));
        assert!(e.contains("plan #1") && e.contains("no such point"), "{e}");
        for h in ["0", "-1", "169", "nan"] {
            let e = err(&plan("B1/F1/R1", h));
            assert!(e.contains("hours"), "{h}: {e}");
        }
        let e = err(&format!("{}\n[[plan]]\npoint = \"B1/F1/R1\"\nhours = 2\n", plan("B1/F1/R1", "8")));
        assert!(e.contains("plan #2") && e.contains("twice"), "{e}");
        let e = err(&format!("{base}\n[[plan]]\npoint = \"B1/F1/R1\"\nhours = 1\nminutes = 3\n"));
        assert!(e.contains("unknown field"), "{e}");
    }

    #[test]
    fn point_in_polygon() {
        let sq = [[0.0, 0.0], [2.0, 0.0], [2.0, 2.0], [0.0, 2.0]];
        assert!(contains(&sq, [1.0, 1.0]));
        assert!(!contains(&sq, [3.0, 1.0]));
        assert_eq!(centroid(&sq), [1.0, 1.0]);
    }

    #[test]
    fn booster_kind_and_mac_bssid_normalization() {
        let spec = r#"
[[unit_type]]
id = "flat"
width_m = 10.0
depth_m = 8.0
rooms = [{ id = "H", rect = [0, 0, 10, 8] }]
points = [{ id = "router", at = [9.0, 7.0], kind = "router", mac = "02-00-00-00-00-01" }]

[[building]]
id = "B1"
units = [{ id = "F1", type = "flat", floor = 0 }]

[[point]]
id = "B1/F1/boost1"
name = "Hall booster"
at = [2.0, 2.0]
kind = "booster"
bssids = ["02:00:00:00:00:0A", "02-00-00-00-00-0b"]
notes = "Wall plug repeater"
"#;
        let s = Site::parse(spec).unwrap();
        let router = s.point("B1/F1/router").unwrap();
        assert_eq!(router.mac.as_deref(), Some("02:00:00:00:00:01"));
        let b = s.point("B1/F1/boost1").unwrap();
        assert_eq!(b.kind, PointKind::Booster);
        assert_eq!(b.bssids, vec!["02:00:00:00:00:0a", "02:00:00:00:00:0b"]);
        assert_eq!(b.notes.as_deref(), Some("Wall plug repeater"));
        let j = s.to_json();
        let pts = j["buildings"][0]["floors"][0]["units"][0]["points"].as_array().unwrap();
        assert!(pts.iter().any(|p| p["kind"] == "booster" && p["bssids"][0] == "02:00:00:00:00:0a"));

        let bad = spec.replace("02-00-00-00-00-01", "not-a-mac");
        assert!(Site::parse(&bad).unwrap_err().to_string().contains("invalid MAC"));
    }

    #[test]
    fn rf_estimate_counts_crossed_walls_and_floors() {
        let spec = r#"
[[unit_type]]
id = "flat"
width_m = 10.0
depth_m = 6.0
rooms = [
  { id = "K", name = "Kitchen", rect = [0, 0, 5, 6] },
  { id = "R1", name = "Bedroom", rect = [5, 0, 5, 6] },
]
walls = [
  { from = [5, 0], to = [5, 6], material = "brick" },
]

[[building]]
id = "B1"
units = [
  { id = "F1", type = "flat", floor = 0 },
  { id = "F2", type = "flat", floor = 1 },
]

# One router for the whole building, in the ground-floor flat only.
[[point]]
id = "B1/F1/router"
at = [1.0, 3.0]
kind = "router"
"#;
        let s = Site::parse(spec).unwrap();
        let same_unit = s.estimate_rf("B1/F1/R1").unwrap();
        assert_eq!(same_unit.router_point, "B1/F1/router");
        assert_eq!(same_unit.walls_crossed, 1);
        assert_eq!(same_unit.floors_crossed, 0);
        assert_eq!(same_unit.obstacle_loss_db, 9.0);

        let upper_floor = s.estimate_rf("B1/F2/R1").unwrap();
        assert_eq!(upper_floor.floors_crossed, 1);
        assert_eq!(upper_floor.walls_crossed, 1);
        assert_eq!(upper_floor.obstacle_loss_db, 24.0);
    }

    #[test]
    fn rf_estimate_prefers_the_router_of_the_same_flat() {
        // Every flat has its own router (router in the unit type): never count a floor.
        let spec = r#"
[[unit_type]]
id = "flat"
width_m = 10.0
depth_m = 6.0
rooms = [
  { id = "K", name = "Kitchen", rect = [0, 0, 5, 6] },
  { id = "R1", name = "Bedroom", rect = [5, 0, 5, 6] },
]
points = [{ id = "router", at = [1.0, 3.0], kind = "router" }]

[[building]]
id = "B1"
units = [
  { id = "F1", type = "flat", floor = 0 },
  { id = "F2", type = "flat", floor = 1 },
]
"#;
        let s = Site::parse(spec).unwrap();
        let rf = s.estimate_rf("B1/F2/R1").unwrap();
        assert_eq!(rf.router_point, "B1/F2/router");
        assert_eq!(rf.floors_crossed, 0);
    }
}
