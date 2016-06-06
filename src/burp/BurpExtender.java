package burp;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.DataOutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory {

	private IExtensionHelpers helpers;

	private IBurpExtenderCallbacks callbacks;

	public JTextField txtHOST;
	public JTextField txtPORT;
	private JLabel lblHOST = new JLabel("Redirector beta v1.2   Redirector HOST : ");
	private JLabel lblPORT = new JLabel("Redirector PORT : ");
	private JPanel mainPanel;
	private String redirectorIP = "127.0.0.1";
	private String redirectorPORT = "9090";

	public static String MENU_ITEM_TEXT = "Send to Redirector";

	// @override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;

		helpers = callbacks.getHelpers();

		callbacks.registerContextMenuFactory(this);

		callbacks.setExtensionName("Redirector");


		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {

				mainPanel = new JPanel();
				mainPanel.setLocation(10, 80);

				mainPanel.setLocation(33, 33);
				txtHOST = new JTextField("127.0.0.1");
				txtPORT = new JTextField("9090");

				lblPORT.setLocation(50, 80);
				txtPORT.setLocation(50, 380);

				callbacks.customizeUiComponent(lblHOST);
				callbacks.customizeUiComponent(txtHOST);

				lblHOST.setLocation(10, 80);
				txtHOST.setLocation(10, 380);
				txtHOST.setMinimumSize(new Dimension(30, 250));

				mainPanel.add(lblHOST);
				mainPanel.add(txtHOST);

				JSeparator newPayloadSeparator = new JSeparator(JSeparator.HORIZONTAL);
				callbacks.customizeUiComponent(newPayloadSeparator);
				newPayloadSeparator.setSize(1000, 10);
				mainPanel.add(newPayloadSeparator);

				mainPanel.add(lblPORT);
				mainPanel.add(txtPORT);

				callbacks.customizeUiComponent(lblPORT);
				callbacks.customizeUiComponent(txtPORT);

				final JButton submit = new JButton("save");
				mainPanel.add(submit);
				callbacks.customizeUiComponent(submit);

				callbacks.customizeUiComponent(mainPanel);

				mainPanel.setLocation(10, 80);
				mainPanel.setSize(500, 100);
				lblHOST.setLocation(10, 80);
				txtHOST.setLocation(10, 380);
				lblPORT.setLocation(50, 80);
				txtPORT.setLocation(50, 380);

				callbacks.addSuiteTab(BurpExtender.this);

				submit.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent e) {
						try {
							String[] ipBlock = txtHOST.getText().toString().split("\\.");
							if (ipBlock.length == 4) {
								redirectorIP = txtHOST.getText().toString();
								redirectorPORT = txtPORT.getText().toString();
								submit.setText("saved...");
							} else {
								submit.setText("saved error | IP could not be verified ->" + ipBlock.length + " | "
										+ txtHOST.getText().toString());
							}
						} catch (Exception e2) {
							submit.setText("saved error | AlertTab");
							callbacks.issueAlert("Redirector Error: Port is not an integer number");
						}
					}
				});

			}
		});

	}

	@Override
	public String getTabCaption() {
		return "Redirector";
	}

	@Override
	public Component getUiComponent() {
		return mainPanel;
	}

	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {

		final IHttpRequestResponse requests[] = invocation.getSelectedMessages();

		List<JMenuItem> ret = new LinkedList<JMenuItem>();

		JMenuItem menuItem = new JMenuItem(MENU_ITEM_TEXT);

		menuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				retrieveURLoverRedirector(requests);
			}
		});

		ret.add(menuItem);
		return (ret);

	}

	public void retrieveURLoverRedirector(IHttpRequestResponse requestResponse[]) {

		for (IHttpRequestResponse rr : requestResponse) {
			IRequestInfo info = helpers.analyzeRequest(rr);
			
			List headers = info.getHeaders();

			String request = new String(rr.getRequest());
			String reqInfoMesBody = request.substring(info.getBodyOffset());

			System.setProperty("https.proxyHost", redirectorIP);
			System.setProperty("https.proxyPort", redirectorPORT);

			try {

				SSLContext sslContext = SSLContext.getInstance("SSL");

				// set up a TrustManager that trusts everything
				sslContext.init(null, new TrustManager[] { new X509TrustManager() {
					public X509Certificate[] getAcceptedIssuers() {
						System.out.println("getAcceptedIssuers =============");
						return null;
					}

					public void checkClientTrusted(X509Certificate[] certs, String authType) {
						System.out.println("checkClientTrusted =============");
					}

					public void checkServerTrusted(X509Certificate[] certs, String authType) {
						System.out.println("checkServerTrusted =============");
					}
				} }, new SecureRandom());

				HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

				HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
					public boolean verify(String arg0, SSLSession arg1) {
						System.out.println("hostnameVerifier =============");
						return true;
					}
				});

				Proxy proxyy = new Proxy(Proxy.Type.HTTP,
						new InetSocketAddress(redirectorIP, Integer.parseInt(redirectorPORT)));

				try {
					if (info.getMethod().toString().toUpperCase().equalsIgnoreCase("GET")) {
						URLConnection conn = new URL(info.getUrl().toString()).openConnection(proxyy);

						for (int i = 1; i < headers.size(); i++) {
							try {
								conn.setRequestProperty(headers.get(i).toString().split(":")[0], headers.get(i)
										.toString().substring(headers.get(i).toString().split(":")[0].length() + 1));
							} catch (Exception e) {
							}
						}

						conn.connect();
						conn.getInputStream();

					} else {
						HttpURLConnection conPOST = (HttpURLConnection) new URL(info.getUrl().toString())
								.openConnection(proxyy);

						conPOST.setRequestMethod(info.getMethod().toString().toUpperCase());

						for (int i = 1; i < headers.size(); i++) {
							try {
								conPOST.setRequestProperty(headers.get(i).toString().split(":")[0], headers.get(i)
										.toString().substring(headers.get(i).toString().split(":")[0].length() + 1));
							} catch (Exception e) {
							}
						}

						conPOST.setUseCaches(false);
						conPOST.setDoInput(true);
						conPOST.setDoOutput(true);

						DataOutputStream wr = new DataOutputStream(conPOST.getOutputStream());
						wr.writeBytes(reqInfoMesBody);
						wr.flush();
						wr.close();

						conPOST.connect();
						conPOST.getInputStream();
					}

				} catch (Exception e) {
				}
			} catch (Exception ex) {
				callbacks.issueAlert("Redirector Proxy :" + ex.getMessage().toString());
			}
		}
	}

	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (messageIsRequest) { 
			String req = callbacks.getHelpers().analyzeRequest(messageInfo).toString(); 
		}
	}

}
