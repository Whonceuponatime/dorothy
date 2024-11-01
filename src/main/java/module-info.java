module com.yourpackage {
    requires javafx.controls;
    requires javafx.fxml;
    requires java.logging;
    requires jnetpcap;
    requires java.net.http;
    requires org.apache.logging.log4j;
    requires com.sun.jna;

    opens com.yourpackage to javafx.fxml;
    exports com.yourpackage;
}