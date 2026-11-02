package com.PassBanned.API.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Utilitaire pour extraire la véritable adresse IP publique du client,
 * y compris lorsqu'une passerelle ou un reverse-proxy est présent
 * (Railway, Docker, Cloudflare, Nginx, AWS, Vercel, etc.).
 */
public final class IpAddressUtil {

    private IpAddressUtil() {
        // Constructeur privé pour classe utilitaire
    }

    private static final String[] IP_HEADER_CANDIDATES = {
        "CF-Connecting-IP",     // Cloudflare
        "X-Forwarded-For",      // Standard proxies & load balancers (Railway, AWS ALB, Nginx)
        "X-Real-IP",            // Nginx
        "Proxy-Client-IP",      // Apache HTTP Server
        "WL-Proxy-Client-IP",   // WebLogic Server
        "HTTP_X_FORWARDED_FOR",
        "HTTP_X_FORWARDED",
        "HTTP_X_CLUSTER_CLIENT_IP",
        "HTTP_CLIENT_IP",
        "HTTP_FORWARDED_FOR",
        "HTTP_FORWARDED"
    };

    /**
     * Récupère automatiquement la requête HTTP active du thread courant
     * et en extrait la véritable IP client.
     */
    public static String getClientIp() {
        try {
            RequestAttributes attribs = RequestContextHolder.getRequestAttributes();
            if (attribs instanceof ServletRequestAttributes servletAttribs) {
                return getClientIp(servletAttribs.getRequest());
            }
        } catch (Exception ignored) {}
        return "127.0.0.1";
    }

    /**
     * Analyse les en-têtes HTTP de routage et reverse-proxy pour identifier l'IP client d'origine.
     *
     * @param request la requête HTTP entrante
     * @return l'adresse IP client (ex: 102.164.23.45 ou 127.0.0.1 en local)
     */
    public static String getClientIp(HttpServletRequest request) {
        if (request == null) {
            return "127.0.0.1";
        }

        for (String header : IP_HEADER_CANDIDATES) {
            String ipList = request.getHeader(header);
            if (ipList != null && !ipList.isBlank() && !"unknown".equalsIgnoreCase(ipList)) {
                // L'en-tête X-Forwarded-For peut contenir une chaîne d'adresses IP :
                // "clientIP, proxy1, proxy2". L'adresse IP d'origine du client est la première.
                String firstIp = ipList.split(",")[0].trim();
                if (!firstIp.isBlank() && !"unknown".equalsIgnoreCase(firstIp)) {
                    // Nettoyage éventuel du port si présent (ex: 192.168.1.5:45210)
                    if (firstIp.contains(":") && !firstIp.contains("::")) {
                        firstIp = firstIp.split(":")[0];
                    }
                    return firstIp;
                }
            }
        }

        // Si aucun en-tête de proxy n'est présent, utiliser l'adresse de connexion directe
        String remoteAddr = request.getRemoteAddr();
        if ("0:0:0:0:0:0:0:1".equals(remoteAddr) || "::1".equals(remoteAddr)) {
            return "127.0.0.1";
        }

        return (remoteAddr != null && !remoteAddr.isBlank()) ? remoteAddr : "127.0.0.1";
    }
}
