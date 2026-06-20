ALTER TABLE user_mfa_profile
    ADD CONSTRAINT chk_user_id_length CHECK (char_length(user_id) <= 255);
