package util;

public enum Response {
    SUCCESS,
    FAIL, /*for generic "server error" type responses*/
    WRONG_INPT, /*user entered username or password is incorrect*/
    NO_SVC,/* used when the requested service is not found. */
    NAUTH, /* used when the user is not logged in, but tries an op other than login */
    USER_EXISTS, /*when username is already taken at registration*/
    CRED_EXISTS /*when adding, the credentials already exist for that service*/
}
