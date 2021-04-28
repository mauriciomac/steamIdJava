import org.expressme.openid.*;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.HashSet;
import java.util.Set;

@WebServlet("/LoginServlet")
public class LoginServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    private OpenIdManager manager;

    static final long ONE_HOUR = 3600000L;
    static final long TWO_HOUR = ONE_HOUR * 2L;
    static final String ATTR_MAC = "openid_mac";
    static final String ATTR_ALIAS = "openid_alias";

    public LoginServlet() {
        super();
    }

    @Override
    public void init() throws ServletException {
        super.init();
        manager = new OpenIdManager();
        manager.setRealm("http://localhost:8080/LoginServlet");
        manager.setReturnTo("http://localhost:8080/LoginServlet?login=verify");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        PrintWriter out = response.getWriter();
        String login = request.getParameter("login");
        if (login != null) {
            if (login.equals("steam")) {
                out.print("<h2>Redirecting</h2>");
                Endpoint endpoint = manager.lookupEndpoint("http://steamcommunity.com/openid");
                Association association = manager.lookupAssociation(endpoint);
                request.getSession().setAttribute(ATTR_MAC, association.getRawMacKey());
                request.getSession().setAttribute(ATTR_ALIAS, endpoint.getAlias());
                String url = manager.getAuthenticationUrl(endpoint, association);
                response.sendRedirect(url);
            } else if (login.equals("verify")) {
                checkNonce(request.getParameter("openid.response_nonce"));
                byte[] mac_key = (byte[]) request.getSession().getAttribute(ATTR_MAC);
                String alias = (String) request.getSession().getAttribute(ATTR_ALIAS);
                //String identity = request.getParameter("openid.identity");

                Authentication authentication = manager.getAuthentication(request, mac_key, alias);
                response.setContentType("text/html; charset=UTF-8");
                showAuthentication(response.getWriter(), authentication);

                //response.getWriter().print(identity);
                return;
            } else if (login.equals("logout")) {
                out.print("<h2>Loggin out</h2>");
            }
            return;
        }
        String id = (String) request.getSession().getAttribute("steamid");
        if (id != null) {
            out.print("<h2>Welcome ");
            out.print(id);
            out.print("</h2>");
            out.print("<a href=\"LoginServlet?login=logout\">Logout</a>");
        } else {
            out.print("<a href=\"LoginServlet?login=steam\">Login</a>");
        }
    }

    void showAuthentication(PrintWriter pw, Authentication auth) {
        pw.print("<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /><title>Test JOpenID</title></head><body><h1>You have successfully signed on!</h1>");
        pw.print("<p>Identity: " + auth.getIdentity() + "</p>");
        pw.print("<p>Email: " + auth.getEmail() + "</p>");
        pw.print("<p>Full name: " + auth.getFullname() + "</p>");
        pw.print("<p>First name: " + auth.getFirstname() + "</p>");
        pw.print("<p>Last name: " + auth.getLastname() + "</p>");
        pw.print("<p>Gender: " + auth.getGender() + "</p>");
        pw.print("<p>Language: " + auth.getLanguage() + "</p>");
        pw.print("</body></html>");
        pw.flush();
    }

    void checkNonce(String nonce) {
        // check response_nonce to prevent replay-attack:
        if (nonce == null || nonce.length() < 20)
            throw new OpenIdException("Verify failed.");
        // make sure the time of server is correct:
        long nonceTime = getNonceTime(nonce);
        long diff = Math.abs(System.currentTimeMillis() - nonceTime);
        if (diff > ONE_HOUR)
            throw new OpenIdException("Bad nonce time.");
        if (isNonceExist(nonce))
            throw new OpenIdException("Verify nonce failed.");
        storeNonce(nonce, nonceTime + TWO_HOUR);
    }

    private Set<String> nonceDb = new HashSet<String>();

    // check if nonce is exist in database:
    boolean isNonceExist(String nonce) {
        return nonceDb.contains(nonce);
    }

    // store nonce in database:
    void storeNonce(String nonce, long expires) {
        nonceDb.add(nonce);
    }

    long getNonceTime(String nonce) {
        try {
            return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ")
                    .parse(nonce.substring(0, 19) + "+0000")
                    .getTime();
        } catch (ParseException e) {
            throw new OpenIdException("Bad nonce time.");
        }
    }
}