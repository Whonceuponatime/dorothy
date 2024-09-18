package com.yourpackage;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application {
    @Override
    public void start(Stage primaryStage) {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("/fxml/main.fxml"));
            primaryStage.setScene(new Scene(loader.load()));
            primaryStage.setTitle("Leeroy - Jenkins Tool");
            primaryStage.show();
        } catch (Exception e) {
            e.printStackTrace(); // Print the stack trace for debugging purposes
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}
