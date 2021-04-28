import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

@WebServlet("/LoginSteamServlet")
public class LoginSteamServlet extends HttpServlet {
    private final SteamOpenID steamOpenID = new SteamOpenID();

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        PrintWriter out = response.getWriter();
        String login = request.getParameter("login");
        if (login != null) {
            if (login.equals("trade")) {
                out.print("<h2>Redirecting</h2>");
                String url = getFullUrl(request, "login=auth");
                String urlAuth = steamOpenID.login(url);
                response.sendRedirect(urlAuth);
            } else if (login.equals("auth")) {
                String url = getFullUrl(request, "login=auth");
                Map<String, String[]> parameterMap = request.getParameterMap();
                String user = steamOpenID.verify(url,parameterMap);
                out.print("<h2>" + user + "</h2>");
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
            out.print("<a href=\"LoginSteamServlet?login=logout\">Logout</a>");
        } else {
            out.print("<a href=\"LoginSteamServlet?login=trade\">Login</a>");
        }
    }

    private String getFullUrl(HttpServletRequest request, String path) {
        StringBuilder builder = new StringBuilder();
        builder.append(request.getScheme());
        builder.append("://");
        builder.append(request.getServerName());
        builder.append(":");
        builder.append(request.getServerPort());
        builder.append(request.getServletPath());
        builder.append(request.getServletPath());
        builder.append("?");
        builder.append(path);
        return builder.toString();
    }
}