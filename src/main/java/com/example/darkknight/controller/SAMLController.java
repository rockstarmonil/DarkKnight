package com.example.darkknight.controller;

import com.example.darkknight.security.CustomUserDetails;
import com.example.darkknight.model.Tenant;
import com.example.darkknight.model.TenantSsoConfig;
import com.example.darkknight.model.User;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.repository.UserRepository;
import com.example.darkknight.service.TenantSsoConfigService;
import com.example.darkknight.util.TenantContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.*;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

@Controller
@RequestMapping("/sso/saml")
public class SAMLController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TenantSsoConfigService ssoConfigService;

    /**
     * Step 1: Initiate SAML Login (redirect to IdP)
     * Uses dynamic tenant-based configuration
     */
    @GetMapping("/login")
    public String initiateSamlLogin(@RequestParam(required = false) String target, Model model) {
        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                System.err.println("❌ No tenant context found");
                return "redirect:/login?error=no_tenant";
            }

            // Get tenant's SAML configuration
            TenantSsoConfig ssoConfig = ssoConfigService.getOrCreateSsoConfig(tenantId);

            // Check if SAML is enabled
            if (!Boolean.TRUE.equals(ssoConfig.getSamlEnabled())) {
                System.err.println("❌ SAML is not enabled for this tenant");
                return "redirect:/login?error=saml_disabled";
            }

            // Validate SAML configuration
            if (!ssoConfigService.validateSamlConfig(ssoConfig)) {
                System.err.println("❌ SAML configuration is incomplete");
                return "redirect:/login?error=saml_not_configured";
            }

            System.out.println("🚀 Initiating SAML login for tenant: " + tenantId);
            System.out.println("🔍 Target URL: " + target);

            String authnRequest = """
                    <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        ID="_%d"
                        Version="2.0"
                        IssueInstant="%s"
                        ProtocolBinding="%s"
                        AssertionConsumerServiceURL="%s">
                        <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml:Issuer>
                        <samlp:NameIDPolicy AllowCreate="true" Format="%s"/>
                    </samlp:AuthnRequest>
                    """.formatted(
                    System.currentTimeMillis(),
                    java.time.Instant.now().toString(),
                    ssoConfig.getSamlSpBinding(),
                    ssoConfig.getSamlSpAcsUrl(),
                    ssoConfig.getSamlSpEntityId(),
                    ssoConfig.getSamlSpNameIdFormat());

            // Deflate + Base64 encode for redirect binding
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            try (DeflaterOutputStream dos = new DeflaterOutputStream(baos, deflater)) {
                dos.write(authnRequest.getBytes(StandardCharsets.UTF_8));
            }

            String samlRequest = Base64.getEncoder().encodeToString(baos.toByteArray());
            String encodedRequest = URLEncoder.encode(samlRequest, StandardCharsets.UTF_8);

            // Add RelayState
            String relayState = (target != null && !target.isEmpty()) ? target : "/dashboard";
            String encodedRelayState = URLEncoder.encode(relayState, StandardCharsets.UTF_8);

            String redirectUrl = ssoConfig.getSamlIdpLoginUrl() +
                    "?SAMLRequest=" + encodedRequest +
                    "&RelayState=" + encodedRelayState;

            System.out.println("🔗 Redirecting to IdP: " + ssoConfig.getSamlIdpLoginUrl());

            return "redirect:" + redirectUrl;

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("❌ SAML initiation error: " + e.getMessage());
            return "redirect:/login?error=" + URLEncoder.encode(e.getMessage(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Step 2: Handle SAML Response (ACS Endpoint)
     * Supports both HTTP-POST binding (IdP POSTs SAMLResponse form field)
     * and HTTP-Redirect binding (IdP GETs with SAMLResponse query param).
     */
    @RequestMapping(value = "/callback", method = { RequestMethod.POST, RequestMethod.GET })
    public String samlCallback(@RequestParam(value = "SAMLResponse", required = false) String samlResponse,
            @RequestParam(value = "RelayState", required = false) String relayState,
            HttpServletRequest request,
            Model model) {
        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                System.err.println("❌ No tenant context in SAML callback");
                model.addAttribute("error", "Invalid tenant context");
                return "error";
            }

            System.out.println("📥 SAML callback received for tenant: " + tenantId);
            System.out.println("📡 HTTP method: " + request.getMethod());
            System.out.println("🔍 RelayState: " + relayState);
            System.out.println("📄 SAMLResponse present: " + (samlResponse != null && !samlResponse.isEmpty()));

            if (samlResponse == null || samlResponse.isEmpty()) {
                System.err.println("❌ Missing SAML Response");
                model.addAttribute("error", "Missing SAML Response");
                return "error";
            }

            // Get tenant
            Tenant tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new RuntimeException("Tenant not found"));

            // Decode SAMLResponse:
            // - HTTP-POST binding: plain Base64 (no compression)
            // - HTTP-Redirect binding: Base64 + DEFLATE compression
            byte[] decodedBytes = Base64.getDecoder().decode(samlResponse.trim());

            // Log first bytes for debugging
            String previewXml = new String(decodedBytes, 0, Math.min(200, decodedBytes.length), StandardCharsets.UTF_8);
            System.out.println(
                    "📋 SAMLResponse preview (raw): " + previewXml.substring(0, Math.min(80, previewXml.length())));

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);

            // Security features to prevent XXE attacks
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

            // Try plain Base64 decode first (POST binding).
            // If it's not valid XML, attempt DEFLATE inflation (Redirect binding).
            Document document;
            try {
                document = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(decodedBytes));
                System.out.println("✅ SAMLResponse decoded via POST binding (no inflation needed)");
            } catch (Exception parseEx) {
                System.out.println("🔄 POST-binding parse failed, trying Redirect binding (DEFLATE inflate)...");
                try (java.util.zip.InflaterInputStream iis = new java.util.zip.InflaterInputStream(
                        new ByteArrayInputStream(decodedBytes),
                        new java.util.zip.Inflater(true))) {
                    byte[] inflated = iis.readAllBytes();
                    System.out.println("✅ SAMLResponse inflated successfully, length: " + inflated.length);
                    document = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(inflated));
                }
            }
            document.getDocumentElement().normalize();

            // Extract NameID (email)
            NodeList nameIdList = document.getElementsByTagNameNS("*", "NameID");
            if (nameIdList.getLength() == 0) {
                System.err.println("❌ NameID not found in SAML response");
                model.addAttribute("error", "Invalid SAML response: NameID not found");
                return "error";
            }
            String nameId = nameIdList.item(0).getTextContent().trim();
            System.out.println("👤 NameID extracted: " + nameId);

            // Validate IdP Issuer if configured
            TenantSsoConfig ssoConfig = ssoConfigService.getOrCreateSsoConfig(tenantId);
            String expectedIssuer = ssoConfig.getSamlIdpEntityId();
            if (expectedIssuer != null && !expectedIssuer.isBlank()) {
                NodeList issuerNodes = document.getElementsByTagNameNS("*", "Issuer");
                if (issuerNodes.getLength() > 0) {
                    String responseIssuer = issuerNodes.item(0).getTextContent().trim();
                    if (!expectedIssuer.equals(responseIssuer)) {
                        System.err.println(
                                "⚠️ SAML Issuer mismatch — expected: " + expectedIssuer + ", got: " + responseIssuer);
                        // Warn but do not block — strict enforcement can be enabled later
                    }
                }
            }

            // Extract attributes
            String extractedFirstName = "SAML User";
            String extractedLastName = "";
            NodeList attrNodes = document.getElementsByTagNameNS("*", "Attribute");

            for (int i = 0; i < attrNodes.getLength(); i++) {
                Node attrNode = attrNodes.item(i);
                if (attrNode.getAttributes() != null && attrNode.getAttributes().getNamedItem("Name") != null) {
                    String attrName = attrNode.getAttributes().getNamedItem("Name").getNodeValue();

                    if ("firstName".equalsIgnoreCase(attrName) || "givenName".equalsIgnoreCase(attrName)) {
                        NodeList values = attrNode.getChildNodes();
                        for (int j = 0; j < values.getLength(); j++) {
                            if (values.item(j).getNodeName().contains("AttributeValue")) {
                                extractedFirstName = values.item(j).getTextContent();
                                break;
                            }
                        }
                    }

                    if ("lastName".equalsIgnoreCase(attrName) || "surname".equalsIgnoreCase(attrName)) {
                        NodeList values = attrNode.getChildNodes();
                        for (int j = 0; j < values.getLength(); j++) {
                            if (values.item(j).getNodeName().contains("AttributeValue")) {
                                extractedLastName = values.item(j).getTextContent();
                                break;
                            }
                        }
                    }
                }
            }

            final String firstNameFinal = extractedFirstName;
            final String lastNameFinal = extractedLastName;

            // Find or create user for this tenant
            Optional<User> existingUser = userRepository.findByEmailAndTenantId(nameId, tenantId);
            User user = existingUser.orElseGet(() -> {
                System.out.println("➕ Creating new SAML user: " + nameId);
                User newUser = new User();
                newUser.setEmail(nameId);
                newUser.setUsername(nameId);
                newUser.setFirstName(firstNameFinal);
                newUser.setLastName(lastNameFinal);
                newUser.setRole("ROLE_USER");
                newUser.setEnabled(true);
                newUser.setTenant(tenant);
                newUser.setCreatedAt(LocalDateTime.now());
                newUser.setUpdatedAt(LocalDateTime.now());
                return newUser;
            });

            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);
            System.out.println("💾 User saved: " + user.getEmail());

            // Setup session
            HttpSession session = request.getSession(true);
            session.setAttribute("isLoggedIn", true);
            session.setAttribute("user", user);
            session.setAttribute("samlAuthenticated", true);

            // Setup Spring Security — principal must be CustomUserDetails so that
            // /dashboard and other controllers can cast it correctly
            CustomUserDetails userDetails = new CustomUserDetails(user);
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(user.getRole()));

            var auth = new UsernamePasswordAuthenticationToken(
                    userDetails, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

            System.out.println("✅ SAML login successful for: " + user.getEmail());

            // Determine redirect URL
            String redirectUrl = "/dashboard";
            if (relayState != null && !relayState.isEmpty()) {
                if (relayState.startsWith("/") && !relayState.startsWith("//")) {
                    redirectUrl = relayState;
                }
            }

            // Redirect to tenant-admin if user is admin
            if ("ROLE_ADMIN".equals(user.getRole())) {
                redirectUrl = "/tenant-admin/dashboard";
            }

            System.out.println("🎯 Redirecting to: " + redirectUrl);
            return "redirect:" + redirectUrl;

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("❌ SAML callback error: " + e.getMessage());
            model.addAttribute("error", "SAML Exception: " + e.getMessage());
            return "error";
        }
    }

    /**
     * Step 3: Generate Metadata (for IdP setup)
     */
    @GetMapping(value = "/metadata", produces = "application/xml")
    @ResponseBody
    public String samlMetadata() {
        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                return "<error>No tenant context</error>";
            }

            TenantSsoConfig ssoConfig = ssoConfigService.getOrCreateSsoConfig(tenantId);

            if (!Boolean.TRUE.equals(ssoConfig.getSamlEnabled())) {
                return "<error>SAML not enabled for this tenant</error>";
            }

            System.out.println("📄 Generating SAML metadata for tenant: " + tenantId);

            String certContent = loadCertificate(ssoConfig);

            String metadata = """
                    <?xml version="1.0" encoding="UTF-8"?>
                    <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
                        <SPSSODescriptor
                            AuthnRequestsSigned="false"
                            WantAssertionsSigned="true"
                            protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                            <KeyDescriptor use="signing">
                                <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                                    <X509Data>
                                        <X509Certificate>%s</X509Certificate>
                                    </X509Data>
                                </KeyInfo>
                            </KeyDescriptor>
                            <NameIDFormat>%s</NameIDFormat>
                            <AssertionConsumerService
                                Binding="%s"
                                Location="%s"
                                index="1"
                                isDefault="true"/>
                        </SPSSODescriptor>
                    </EntityDescriptor>
                    """.formatted(
                    ssoConfig.getSamlSpEntityId(),
                    certContent,
                    ssoConfig.getSamlSpNameIdFormat(),
                    ssoConfig.getSamlSpBinding(),
                    ssoConfig.getSamlSpAcsUrl());

            System.out.println("✅ Metadata generated successfully");
            return metadata;

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("❌ Metadata generation error: " + e.getMessage());
            return "<error>Metadata generation failed: " + e.getMessage() + "</error>";
        }
    }

    /**
     * Load the IdP X.509 certificate for use in SAML metadata.
     * Priority:
     * 1. DB-stored inline cert (samlIdpCertificate field) — set by tenant admin via
     * UI
     * 2. Classpath file path (samlCertificatePath) — legacy fallback
     */
    private String loadCertificate(TenantSsoConfig ssoConfig) throws IOException {
        // 1️⃣ Use DB-stored inline certificate (preferred)
        String inlineCert = ssoConfig.getSamlIdpCertificate();
        if (inlineCert != null && !inlineCert.isBlank()) {
            System.out.println("🔐 Using DB-stored inline certificate");
            // Already normalized (headers stripped) when saved — return as is
            return inlineCert.replaceAll("\\s+", "");
        }

        // 2️⃣ Fall back to classpath file
        String certPath = ssoConfig.getSamlCertificatePath();
        if (certPath == null || certPath.isEmpty()) {
            certPath = "classpath:Custom_SAML_App.cer";
        }
        System.out.println("📂 Loading certificate from classpath: " + certPath);
        String resourcePath = certPath.replace("classpath:", "");
        ClassPathResource resource = new ClassPathResource(resourcePath);
        String cert = StreamUtils.copyToString(resource.getInputStream(), StandardCharsets.UTF_8);
        return cert
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
    }

    /**
     * Logout
     */
    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            User user = (User) session.getAttribute("user");
            if (user != null) {
                System.out.println("👋 Logging out SAML user: " + user.getEmail());
            }
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        System.out.println("✅ SAML logout successful");
        return "redirect:/login?logout";
    }
}