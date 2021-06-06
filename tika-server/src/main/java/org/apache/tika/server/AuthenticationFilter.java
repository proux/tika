package org.apache.tika.server;

import org.apache.cxf.jaxrs.security.SimpleAuthorizingFilter;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.net.URL;
import java.net.HttpURLConnection;
import java.util.List;

public class AuthenticationFilter extends SimpleAuthorizingFilter {
    @Override
    public void filter(ContainerRequestContext context) {
        MultivaluedMap<String, String> authHeaders = context.getHeaders();
        List<String> keys = authHeaders.get("X-TIKA-KEY");

        if (!context.getUriInfo().getPath().equals("/") && System.getenv("TIKAUSE") != null && System.getenv("TIKAUSE").equals("1")) {
            if (keys != null && !keys.isEmpty()) {
                if (!keys.get(0).isEmpty()) {
                    try {
                        URL url = new URL(System.getenv("TIKAURL"));
                        HttpURLConnection con = (HttpURLConnection) url.openConnection();
                        con.setRequestProperty("X-TIKA-KEY", keys.get(0));
                        con.setRequestProperty("Content-Length", "0");
                        if (context.getMethod().equals(HttpMethod.POST) || context.getMethod().equals(HttpMethod.PUT)) {
                            con.setRequestMethod("POST");
                        } else {
                            con.setRequestMethod("GET");
                        }
                        int status = con.getResponseCode();
                        if (status >= 200 && status < 399) {
                            return;
                        }
                    } catch (Exception e) {
                        context.abortWith(Response.status(Response.Status.FORBIDDEN).build());
                    }
                }
            }
            context.abortWith(Response.status(Response.Status.FORBIDDEN).build());
        }
    }

}