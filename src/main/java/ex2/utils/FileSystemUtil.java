package ex2.utils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/*
* Classe qui encapsules les opérations de fichier du programme
* */
public class FileSystemUtil {

    private static final String CURRENT_DIRECTORY_PROPERTY = "user.dir";

    /*
    * Fonction qui permet d'ajouter le String 'toAdd' au fichier texte 'fileName' spécifié en paramètre
    * */
    public static void appendToFile(String toAdd, String fileName) throws IOException {
        Path filePath = getFilePath(fileName);
        BufferedWriter fileWriter = new BufferedWriter(new FileWriter(filePath.toString(), true));
        fileWriter.append(toAdd + System.lineSeparator()); //ajout au fichier existant
        fileWriter.close();
    }

    /*
    * Fonction qui permet de lire une entrée dans le fichier 'fileName'.
    * Cette fonction retourne la première ligne qui respecte la condition suivante:
    * - contient l'identifiant 'lineIdentifier' à l'indexe 'lineIdentifierIndex' de la ligne séparée par le séparateur 'separator'
    *
    * Retourne null si pas trouvé.
    * */
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

    /*
    * Fonction qui initialise le fichier 'filePath'.
    * Si le dossier parent du fichier n'existe pas, il est créé. (1 niveau supporté)
    * Si le fichier lui-même n'existe pas il est créé.
    * Sinon, rien n'est fait.
    * */
    private static void initializeFile(Path filePath) throws IOException {
        File file = filePath.toFile();
        File directory = new File(file.getParentFile().getAbsolutePath());
        directory.mkdirs();
        file.createNewFile();
    }

    /*
    * Fonction qui retourne le chemain de fichier pour 'fileName'. Si le fichier n'existe pas il est créé avant.
    * */
    private static Path getFilePath(String fileName) throws IOException {
        String currentPath = System.getProperty(CURRENT_DIRECTORY_PROPERTY);
        Path filePath = Paths.get(currentPath, fileName);
        initializeFile(filePath);
        return filePath;
    }

    /*
    * Fonction qui retourne tous les lignes dans un fichier dont le chemain est 'targetFile'
    * */
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
