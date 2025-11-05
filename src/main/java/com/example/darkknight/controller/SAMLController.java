package com.example.darkknight.controller;

import com.example.darkknight.model.User;
import com.example.darkknight.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
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
import java.util.Base64;

@Controller
@RequestMapping("/sso/saml")
public class SAMLController {

    private final UserRepository userRepository;

    @Value("${saml.enabled:true}")
    private boolean samlEnabled;

    @Value("${saml.idp.login-url}")
    private String idpLoginUrl;

    @Value("${saml.sp.entity-id}")
    private String spEntityId;

    @Value("${saml.sp.acs-url}")
    private String acsUrl;

    @Value("${saml.sp.binding:urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST}")
    private String binding;

    @Value("${saml.sp.nameid-format:urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress}")
    private String nameIdFormat;

    @Value("${saml.certificate.path:classpath:Custom_SAML_App.cer}")
    private Resource certificatePath;

    public SAMLController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /** Step 1️⃣: Initiate SAML Login (redirect to IdP) */
    @GetMapping("/initiate")
    public String initiateSamlLogin(@RequestParam(required = false) String target) {
        try {
            if (!samlEnabled) {
                return "redirect:/error?message=SAML+is+disabled";
            }

            System.out.println("🚀 Initiating SAML login...");
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
                    """.formatted(System.currentTimeMillis(),
                    java.time.Instant.now().toString(),
                    binding,
                    acsUrl,
                    spEntityId,
                    nameIdFormat);

            // Deflate + Base64 encode for redirect binding
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            try (DeflaterOutputStream dos = new DeflaterOutputStream(baos, deflater)) {
                dos.write(authnRequest.getBytes(StandardCharsets.UTF_8));
            }

            String samlRequest = Base64.getEncoder().encodeToString(baos.toByteArray());
            String encodedRequest = URLEncoder.encode(samlRequest, StandardCharsets.UTF_8);

            // Add RelayState to tell IdP where to redirect after authentication
            String relayState = (target != null && !target.isEmpty()) ? target : "/user-dashboard";
            String encodedRelayState = URLEncoder.encode(relayState, StandardCharsets.UTF_8);

            String redirectUrl = idpLoginUrl + "?SAMLRequest=" + encodedRequest + "&RelayState=" + encodedRelayState;
            System.out.println("🔗 Redirecting to IdP: " + idpLoginUrl);

            return "redirect:" + redirectUrl;
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("❌ SAML initiation error: " + e.getMessage());
            return "redirect:/error?message=" + URLEncoder.encode("SAML Error: " + e.getMessage(), StandardCharsets.UTF_8);
        }
    }

    /** Step 2️⃣: Handle SAML Response (ACS Endpoint) */
    @PostMapping("/callback")
    public String samlCallback(@RequestParam(value = "SAMLResponse", required = false) String samlResponse,
                               @RequestParam(value = "RelayState", required = false) String relayState,
                               HttpServletRequest request,
                               Model model) {
        try {
            System.out.println("📥 SAML callback received");
            System.out.println("🔍 Request URL: " + request.getRequestURL());
            System.out.println("🔍 RelayState: " + relayState);
            System.out.println("🔍 SAMLResponse present: " + (samlResponse != null && !samlResponse.isEmpty()));

            if (samlResponse == null || samlResponse.isEmpty()) {
                System.err.println("❌ Missing SAML Response");
                model.addAttribute("error", "Missing SAML Response");
                return "error";
            }

            // Decode and parse SAML response
            byte[] decodedBytes = Base64.getDecoder().decode(samlResponse);
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);

            // Security features to prevent XXE attacks
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

            Document document = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(decodedBytes));
            document.getDocumentElement().normalize();

            // Extract NameID (usually the email)
            NodeList nameIdList = document.getElementsByTagNameNS("*", "NameID");
            if (nameIdList.getLength() == 0) {
                System.err.println("❌ NameID not found in SAML response");
                model.addAttribute("error", "Invalid SAML response: NameID not found");
                return "error";
            }
            String nameId = nameIdList.item(0).getTextContent().trim();
            System.out.println("👤 NameID extracted: " + nameId);

            // Extract first name if available
            String extractedFirstName = "SAML User";
            NodeList attrNodes = document.getElementsByTagNameNS("*", "Attribute");
            for (int i = 0; i < attrNodes.getLength(); i++) {
                Node attrNode = attrNodes.item(i);
                if (attrNode.getAttributes() != null && attrNode.getAttributes().getNamedItem("Name") != null) {
                    String attrName = attrNode.getAttributes().getNamedItem("Name").getNodeValue();
                    System.out.println("🔍 Found attribute: " + attrName);

                    if ("firstName".equalsIgnoreCase(attrName) || "givenName".equalsIgnoreCase(attrName)) {
                        NodeList values = attrNode.getChildNodes();
                        for (int j = 0; j < values.getLength(); j++) {
                            if (values.item(j).getNodeName().contains("AttributeValue")) {
                                extractedFirstName = values.item(j).getTextContent();
                                System.out.println("✅ First name extracted: " + extractedFirstName);
                                break;
                            }
                        }
                    }
                }
            }

            // Make effectively final copy for lambda
            final String firstNameFinal = extractedFirstName;

            // Save or update user in database
            Optional<User> existingUser = userRepository.findByEmail(nameId);
            User user = existingUser.orElseGet(() -> {
                System.out.println("➕ Creating new user: " + nameId);
                User newUser = new User();
                newUser.setEmail(nameId);
                newUser.setUsername(nameId);
                newUser.setFirstName(firstNameFinal);
                newUser.setEnabled(true);
                newUser.setCreatedAt(LocalDateTime.now());
                newUser.setUpdatedAt(LocalDateTime.now());
                return newUser;
            });

            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);
            System.out.println("💾 User saved: " + user.getEmail());

            // Setup HTTP session
            HttpSession session = request.getSession(true);
            session.setAttribute("isLoggedIn", true);
            session.setAttribute("user", user);
            session.setAttribute("samlResponse", samlResponse);

            // Setup Spring Security context
            var authority = new SimpleGrantedAuthority("ROLE_USER");
            var auth = new UsernamePasswordAuthenticationToken(
                    user.getEmail(), null, Collections.singletonList(authority));
            SecurityContextHolder.getContext().setAuthentication(auth);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

            System.out.println("✅ SAML login successful for: " + user.getEmail());

            // Determine redirect URL from RelayState or use default
            String redirectUrl = "/user-dashboard";
            if (relayState != null && !relayState.isEmpty()) {
                // Validate RelayState to prevent open redirect vulnerabilities
                if (relayState.startsWith("/") && !relayState.startsWith("//")) {
                    redirectUrl = relayState;
                    System.out.println("🔄 Using RelayState redirect: " + redirectUrl);
                } else {
                    System.out.println("⚠️ Invalid RelayState, using default: " + redirectUrl);
                }
            }

            System.out.println("🎯 Final redirect URL: " + redirectUrl);
            return "redirect:" + redirectUrl;

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("❌ SAML callback error: " + e.getMessage());
            model.addAttribute("error", "SAML Exception: " + e.getMessage());
            return "error";
        }
    }

    /** Step 3️⃣: Generate Metadata (for IdP setup) */
    @GetMapping(value = "/metadata", produces = "application/xml")
    @ResponseBody
    public String samlMetadata() {
        try {
            System.out.println("📄 Generating SAML metadata");
            String certContent = loadCertificate();

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
                    """.formatted(spEntityId, certContent, nameIdFormat, binding, acsUrl);

            System.out.println("✅ Metadata generated successfully");
            System.out.println("🔗 ACS URL in metadata: " + acsUrl);
            return metadata;

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("❌ Metadata generation error: " + e.getMessage());
            return "<error>Metadata generation failed: " + e.getMessage() + "</error>";
        }
    }

    private String loadCertificate() throws IOException {
        String cert = StreamUtils.copyToString(certificatePath.getInputStream(), StandardCharsets.UTF_8);
        return cert
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
    }

    /** Step 4️⃣: User Dashboard */
    @GetMapping("/dashboard")
    public String dashboard(HttpServletRequest request, Model model) {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("isLoggedIn") == null) {
            System.out.println("⚠️ Unauthorized dashboard access - redirecting to login");
            return "redirect:/login";
        }

        User user = (User) session.getAttribute("user");
        if (user == null) {
            System.out.println("⚠️ User not found in session - redirecting to login");
            return "redirect:/login";
        }

        System.out.println("✅ Dashboard accessed by: " + user.getEmail());
        model.addAttribute("user", user);
        return "user-dashboard";
    }

    /** Step 5️⃣: Logout */
    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            User user = (User) session.getAttribute("user");
            if (user != null) {
                System.out.println("👋 Logging out user: " + user.getEmail());
            }
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        System.out.println("✅ Logout successful");
        return "redirect:/login?logout";
    }

    /** Debug endpoint - Remove in production */
    @GetMapping("/debug")
    @ResponseBody
    public Map<String, String> debugInfo() {
        Map<String, String> info = new HashMap<>();
        info.put("samlEnabled", String.valueOf(samlEnabled));
        info.put("idpLoginUrl", idpLoginUrl);
        info.put("spEntityId", spEntityId);
        info.put("acsUrl", acsUrl);
        info.put("binding", binding);
        info.put("nameIdFormat", nameIdFormat);
        return info;
    }
}