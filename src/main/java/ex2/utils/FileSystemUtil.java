package ex2.utils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Scanner;

public class FileSystemUtil {

    private static final String CURRENT_DIRECTORY_PROPERTY = "user.dir";

    public static void appendToFile(String toAdd, String fileName) throws IOException {
        Path filePath = getFilePath(fileName);
        BufferedWriter fileWriter = new BufferedWriter(new FileWriter(filePath.toString(), true));
        fileWriter.append(toAdd + System.lineSeparator()); //ajout au fichier existant
        fileWriter.close();
    }

    public static String readLineEntry(String lineIdentifier, String fileName) throws IOException {
        Path filePath = getFilePath(fileName);
        File file = filePath.toFile();
        Scanner fileScanner = new Scanner(file);

        while (fileScanner.hasNextLine()) {
            String lineContent = fileScanner.nextLine();
            if (lineContent.startsWith(lineIdentifier)) {
                return lineContent;
            }
        }
         return null;
    }

    private static void initializeFile(Path filePath) throws IOException {
        File file = filePath.toFile();
        file.createNewFile();
    }

    private static Path getFilePath(String fileName) throws IOException {
        String currentPath = System.getProperty(CURRENT_DIRECTORY_PROPERTY);
        Path filePath = Paths.get(currentPath, fileName);
        initializeFile(filePath);
        return filePath;
    }
}
