use agentclean::docker::{
    classify_volume, parse_builder_du_json, parse_container_inspect_json, parse_container_ls_json,
    parse_image_ls_json, parse_system_df_json, parse_volume_ls_json, VolumeDisposition,
};

#[test]
fn parses_system_df_json_lines_into_stable_records() {
    let input = r#"{"Type":"Images","TotalCount":3,"Active":1,"Size":"1.2GB","Reclaimable":"400MB (33%)"}
{"Type":"Containers","TotalCount":2,"Active":1,"Size":"20MB","Reclaimable":"10MB (50%)"}"#;
    let rows = parse_system_df_json(input).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].kind, "Images");
    assert_eq!(rows[0].total_count, Some(3));
    assert_eq!(rows[1].reclaimable, "10MB (50%)");
}

#[test]
fn parses_object_fixtures_without_brittle_human_output() {
    let builder =
        parse_builder_du_json(r#"{"ID":"abc","Parent":"","Reclaimable":true,"Size":"4MB"}"#)
            .unwrap();
    assert_eq!(builder[0].id, "abc");
    assert!(builder[0].reclaimable);

    let volumes = parse_volume_ls_json(r#"{"Name":"pg_data","Driver":"local","Labels":"com.example.db=postgres","Mountpoint":"/var/lib/docker/volumes/pg_data/_data"}"#).unwrap();
    assert_eq!(volumes[0].name, "pg_data");
    assert_eq!(
        volumes[0].labels.get("com.example.db").map(String::as_str),
        Some("postgres")
    );

    let containers = parse_container_ls_json(r#"{"ID":"123","Names":"db","Image":"postgres:16","Mounts":"pg_data:/var/lib/postgresql/data","Labels":"com.example.role=db"}"#).unwrap();
    assert_eq!(containers[0].names, "db");
    assert!(containers[0].mounts.contains("pg_data"));

    let images = parse_image_ls_json(
        r#"{"ID":"sha256:abc","Repository":"postgres","Tag":"16","Size":"400MB"}"#,
    )
    .unwrap();
    assert_eq!(images[0].repository, "postgres");
}

#[test]
fn parses_volume_references_from_inspect_mounts_not_display_text() {
    let names = parse_container_inspect_json(
        r#"[{"Id":"abc","Mounts":[{"Type":"volume","Name":"pg_data"},{"Type":"bind","Source":"/tmp"}]}]"#,
    )
    .unwrap();
    assert_eq!(names, vec!["pg_data"]);
}

#[test]
fn rejects_records_missing_identity_fields() {
    assert!(parse_image_ls_json(r#"{"Repository":"x"}"#).is_err());
    assert!(parse_volume_ls_json(r#"{"Driver":"local"}"#).is_err());
}

#[test]
fn classifies_db_and_referenced_volumes_as_protected() {
    let db = classify_volume("postgres_data", "", true);
    assert_eq!(
        db,
        VolumeDisposition::Protected {
            reason: "database-like name".into()
        }
    );
    let referenced = classify_volume("cache", "", true);
    assert_eq!(
        referenced,
        VolumeDisposition::Protected {
            reason: "referenced by container".into()
        }
    );
    assert_eq!(
        classify_volume("cache", "", false),
        VolumeDisposition::Dangerous {
            reason: "unreferenced volume may contain data".into()
        }
    );
}
