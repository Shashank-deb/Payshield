package com.payshield.frauddetector.infrastructure.parser;

import com.payshield.frauddetector.application.InvoiceDetectionService;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.parser.AutoDetectParser;
import org.apache.tika.sax.BodyContentHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class TikaPdfParser implements InvoiceDetectionService.PdfParser {

    @Override
    public InvoiceDetectionService.Parsed parse(Path storedPath) {
        try (InputStream inputStream = Files.newInputStream(storedPath)) {
            // Use Apache Tika to extract text from binary PDF file
            BodyContentHandler handler = new BodyContentHandler(-1); // -1 = unlimited
            Metadata metadata = new Metadata();
            AutoDetectParser parser = new AutoDetectParser();
            parser.parse(inputStream, handler, metadata);

            String text = handler.toString();

            InvoiceDetectionService.Parsed p = new InvoiceDetectionService.Parsed();
            p.vendorName = match(text, "(?i)Vendor[:\\s]+([A-Za-z0-9&.,\\-\\s]{2,})");
            p.currency   = match(text, "(?i)Currency[:\\s]+([A-Z]{3})");
            p.bankIban   = match(text, "(?i)([A-Z]{2}\\d{2}[A-Z0-9]{13,30})");
            p.bankSwift  = match(text, "(?i)\\b([A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?)\\b");
            String last4 = match(text, "(?i)account(?:\\s*number)?[:\\s\\-]*\\*{0,12}([0-9]{4})\\b");
            if (last4 == null && p.bankIban != null && p.bankIban.length() >= 4) {
                last4 = p.bankIban.substring(p.bankIban.length() - 4);
            }
            p.bankLast4 = last4;

            String amt = match(text, "(?i)(?:Total|Amount)[:\\s]*([0-9]{1,3}(?:[,\\s][0-9]{3})*(?:\\.[0-9]{2})?)");
            if (amt != null) {
                try {
                    p.amount = new BigDecimal(amt.replaceAll("[,\\s]", ""));
                } catch (Exception ignore) {
                    // Log or handle if needed
                }
            }

            return p;

        } catch (Exception e) {
            throw new RuntimeException("Failed to parse stored PDF file: " + storedPath, e);
        }
    }

    private static String match(String t, String re) {
        Matcher m = Pattern.compile(re).matcher(t);
        return m.find() ? m.group(1).trim() : null;
    }
}
