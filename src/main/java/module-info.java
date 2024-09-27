module com.yourpackage {
    requires javafx.controls;
    requires javafx.fxml;
    requires java.logging;
    requires javafx.graphics;
    requires java.net.http;
    requires jnetpcap;

    opens com.yourpackage to javafx.fxml;
    exports com.yourpackage;
}
