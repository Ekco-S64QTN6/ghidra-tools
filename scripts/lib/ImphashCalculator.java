package lib;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * Calculates standard PE Import Hash (imphash) for PE executables.
 * Imphash is the MD5 of ordered "library.function" strings in lowercase,
 * with standard extensions removed (.dll, .sys, .ocx).
 */
public class ImphashCalculator {

    public static String calculateImphash(Program program) {
        String fmt = program.getExecutableFormat();
        if (fmt == null || (!fmt.contains("Portable Executable") && !fmt.toUpperCase().contains("PE"))) {
            return null;
        }

        ExternalManager em = program.getExternalManager();
        String[] libs = em.getExternalLibraryNames();
        if (libs == null || libs.length == 0) {
            return null;
        }

        List<String> importList = new ArrayList<>();

        for (String lib : libs) {
            String cleanLib = lib.toLowerCase();
            if (cleanLib.endsWith(".dll") || cleanLib.endsWith(".sys") || cleanLib.endsWith(".ocx")) {
                int lastDot = cleanLib.lastIndexOf('.');
                cleanLib = cleanLib.substring(0, lastDot);
            }

            ExternalLocationIterator locs = em.getExternalLocations(lib);
            while (locs.hasNext()) {
                ExternalLocation loc = locs.next();
                String func = loc.getLabel();
                if (func != null && !func.isEmpty()) {
                    importList.add(cleanLib + "." + func.toLowerCase());
                }
            }
        }

        if (importList.isEmpty()) {
            return null;
        }

        String joined = String.join(",", importList);
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(joined.getBytes(StandardCharsets.US_ASCII));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b & 0xFF));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }
}
