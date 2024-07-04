

You need to create an Stored Procedure in postgres like this:

CREATE PROCEDURE GET_TOTAL_USERS_BY_GENDER (
	IN gender_in VARCHAR(50)	,
	OUT count_out INT
)
LANGUAGE plpgsql
AS $$
BEGIN
	SELECT COUNT(*) INTO count_out FROM users WHERE gender = gender_in;
END;
$$;
