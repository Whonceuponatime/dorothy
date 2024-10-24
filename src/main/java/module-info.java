module com.yourpackage {
    requires javafx.controls;
    requires javafx.fxml;
    requires org.pcap4j.core;
    requires org.pcap4j.packetfactory.static; // This should match the dependency in your build.gradle
}
