package util;

public enum Response {
    SUCCESS,
    FAIL, /*for generic "server error" type responses*/
    WRONG_INPT, /*user entered username or password is incorrect*/
    NO_SVC,/* used when the requested service is not found. */
    NAUTH, /* used when the user is not logged in, but tries an op other than login */
		LOGGED_IN, /*used when user tries to login when they are already logged in*/
    USER_EXISTS, /*when username is already taken at registration*/
    CRED_EXISTS, /*when adding, the credentials already exist for that service*/
    DUP_LOGIN, /*when user is trying to login again after logging in successfully */
    BAD_FORMAT, /* when user entered ill formatted password, username, or otherwise */
		MAC,
		BAD_CODE /*when user entered wrong code for two step code verification*/
}
