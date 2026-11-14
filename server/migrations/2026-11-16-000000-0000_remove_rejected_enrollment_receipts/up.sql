DELETE FROM application_kv
WHERE substr(key, 1, 26) = 'control_enrollment_result/'
  AND CASE WHEN json_valid(value) THEN
    CASE WHEN json_type(value, '$.result') = 'text'
              AND json_valid(json_extract(value, '$.result')) THEN
      json_type(json_extract(value, '$.result'), '$.Rejected') = 'text'
      AND json_type(json_extract(value, '$.result'), '$.Enrolled') IS NULL
    ELSE 0 END
  ELSE 0 END;
