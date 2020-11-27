package ex2.utils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class FileSystemUtil {

    private static final String CURRENT_DIRECTORY_PROPERTY = "user.dir";

    public static void appendToFile(String toAdd, String fileName) throws IOException {
        Path filePath = getFilePath(fileName);
        BufferedWriter fileWriter = new BufferedWriter(new FileWriter(filePath.toString(), true));
        fileWriter.append(toAdd + System.lineSeparator()); //ajout au fichier existant
        fileWriter.close();
    }

    public static String readLineEntry(String lineIdentifier, int lineIdentifierIndex, String separator, String fileName) throws IOException {
        Path filePath = getFilePath(fileName);
        File file = filePath.toFile();
        Scanner fileScanner = new Scanner(file);

        while (fileScanner.hasNextLine()) {
            String lineContent = fileScanner.nextLine();
            String[] lineContentArr = lineContent.split(separator);
            if (lineContentArr.length < lineIdentifierIndex + 1)
                return null;

            if (lineContentArr[lineIdentifierIndex].equals(lineIdentifier)) {
                return lineContent;
            }
        }
         return null;
    }

    private static void initializeFile(Path filePath) throws IOException {
        File file = filePath.toFile();
        File directory = new File(file.getParentFile().getAbsolutePath());
        directory.mkdirs();
        file.createNewFile();
    }

    private static Path getFilePath(String fileName) throws IOException {
        String currentPath = System.getProperty(CURRENT_DIRECTORY_PROPERTY);
        Path filePath = Paths.get(currentPath, fileName);
        initializeFile(filePath);
        return filePath;
    }

    public static List<String> getAllLinesInFile(String targetFile) throws IOException {
        List<String> lines = new ArrayList<>();

        //try-with-resources : il faut fermer le reader s'il y a un problème
        try (BufferedReader reader = new BufferedReader(new FileReader(targetFile))) {
            String line = reader.readLine();
            while (line != null) {
                lines.add(line);
                line = reader.readLine();
            }
        }

        return lines;
    }
}
