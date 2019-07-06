import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

import javax.xml.bind.DatatypeConverter;

public class WOLService {
	public static void main(String[] args) {
		// default values
		String secureOnPw = "0000AAAA0000";
		String IP = "192.168.0.255";
		int PORT = 9;		
		
		//        PORT = args[0]
		//          IP = args[1]
		// secureOn PW = args[2]
		if(args.length == 0 || args.length>3){
			System.out.println("Usage: WOLService <port> [IP] [SecureOnPassword]");
			return;
		}
		if(args.length>0){
			try{
				PORT = Integer.parseInt(args[0]);
			}catch(Exception e){
				System.out.println("Usage: WOLService <port> [IP] [SecureOnPassword]");
				return;
			}
		}
		if(args.length>1){
			IP = args[1];
		}
		if(args.length>2){
			secureOnPw = args[2];
			if(secureOnPw.length()!=12){
				System.out.println("SecureOn Password has to be 12 HEX digits, example: 00FF00FF00FF");
				return;
			}
		}
		
		System.out.println("Server listening on port: " + PORT);
		System.out.println("Forwarding packets to: " + IP);
		System.out.println("SecureOn PW: " + secureOnPw);

		
		try {
			@SuppressWarnings("resource")
			DatagramSocket serverSocket = new DatagramSocket(PORT);
			byte[] receiveData = new byte[1024];
			//byte[] sendData = new byte[1024];

			while (true) {
				DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
				serverSocket.receive(receivePacket);
				byte[] packetData = receivePacket.getData();
				String packetString = DatatypeConverter.printHexBinary(packetData);

				// check format of Magic Packet
				boolean check = true;
				// Magic packet has to start with FFFFFFFFFFFF
				if (!packetString.substring(0, 12).equals("FFFFFFFFFFFF"))
					check = false;
				// MAC Address has to be repeated 16 times
				for (int i = 12; i <= 12 * 15; i += 12) {
					// System.out.println(packetString.substring(i, i + 12) +
					// " = " + packetString.substring(i + 12, i + 24));
					if (!packetString.substring(i, i + 12).equals(
							packetString.substring(i + 12, i + 24))) {
						check = false;
					}
				}

				// Filter out packets coming from LAN 
				if (packetString.substring(204, 216).equals(secureOnPw)) {
					// If magic packet passes test, proceed and send WOL packet
					if (check) {
						byte[] mac = new byte[6];
						System.arraycopy(packetData, 6, mac, 0, 6);
						String macString = DatatypeConverter.printHexBinary(mac);
						InetAddress IPAddress = receivePacket.getAddress();
						int port = receivePacket.getPort();
						System.out.println("Received from " + IPAddress + ":" + port + " MAC= "
								+ macString);
						//System.out.println(packetString);
						sendMagicPacket(IP, mac, PORT);
					} else {
						System.out.println("WOL packet format error");
					}
				}
			}
		} catch (SocketException e) {
			System.err.println("Could not open Socket on port "+PORT);
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void sendMagicPacket(String ipStr, byte[] macBytes, int PORT) {
		try {
			System.out.println("Sending Magic packet to " + ipStr);
			byte[] bytes = new byte[6 + 16 * macBytes.length + 6];
			for (int i = 0; i < 6; i++) {
				bytes[i] = (byte) 0xff;
			}
			for (int i = 6; i < bytes.length; i += macBytes.length) {
				System.arraycopy(macBytes, 0, bytes, i, macBytes.length);
			}

			InetAddress address = InetAddress.getByName(ipStr);
			DatagramPacket packet = new DatagramPacket(bytes, bytes.length, address, PORT);
			DatagramSocket socket = new DatagramSocket();
			socket.send(packet);
			socket.close();

			System.out.println("Wake-on-LAN packet sent.");
		} catch (Exception e) {
			System.out.println("Failed to send Wake-on-LAN packet: + e");
			System.exit(1);
		}
	}

}
