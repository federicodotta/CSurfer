package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SpringLayout;
import javax.swing.plaf.LayerUI;

public class CSurferJpanel extends JPanel 
{
	public JTextField maxSessionsTextField;
	public JTextField tokenNameTextField;
	public JTextField sessionIDTextField;
	public JTextField tokenResponseRegexTextField;
	public JTextField tokenMatchGroupTextField;
		
	public JButton saveButton;
	public JButton enableDisableButton;
	public JButton exportConfigButton;
	public JButton loadConfigButton;
	
	public CSurferJpanel()
	{
		
		this.setLayout(new GridLayout(0, 1, 0, 0));
		
		JPanel buttonsPanel = new JPanel();
		buttonsPanel.setLayout(new BoxLayout(buttonsPanel, BoxLayout.X_AXIS));
		buttonsPanel.setAlignmentX(Component.LEFT_ALIGNMENT); 
		
		this.saveButton = new JButton();
		this.saveButton.setText("Save");
		
		this.enableDisableButton = new JButton();
		this.enableDisableButton.setText("Disable");
		
		this.exportConfigButton = new JButton();
		this.exportConfigButton.setText("Export config");
		
		this.loadConfigButton = new JButton();
		this.loadConfigButton.setText("Load config");
		
		this.maxSessionsTextField = new JTextField("", 20);				
		JLabel maxSessionsLabel = new JLabel("Maximum number of sessions");		
		maxSessionsLabel.setLabelFor(maxSessionsTextField);
		
		this.tokenNameTextField = new JTextField("", 20);
		JLabel tokenNameLabel = new JLabel("Anti CSRF token field name in requests");
		tokenNameLabel.setLabelFor(tokenNameTextField);
		
		this.sessionIDTextField = new JTextField("", 20);
		JLabel sessionIDLabel = new JLabel("Session ID parameter name");
		sessionIDLabel.setLabelFor(sessionIDTextField);
		
		this.tokenResponseRegexTextField = new JTextField("", 20);
		JLabel tokenResponseRegexLabel = new JLabel("Regex expression for matching the AntiCSRF token in responses");
		tokenResponseRegexLabel.setLabelFor(tokenResponseRegexTextField);
						
		this.tokenMatchGroupTextField = new JTextField("", 20);
		JLabel tokenMatchGroupLabel = new JLabel("The match group number inside the regex");
		tokenMatchGroupLabel.setLabelFor(tokenMatchGroupTextField);
		
				
		this.add(maxSessionsLabel);
		this.add(maxSessionsTextField);
		
		this.add(tokenNameLabel);
		this.add(tokenNameTextField);
		
		
		this.add(sessionIDLabel);
		this.add(sessionIDTextField);
		
		this.add(tokenResponseRegexLabel);
		this.add(tokenResponseRegexTextField);
		
		this.add(tokenMatchGroupLabel);
		this.add(tokenMatchGroupTextField);
		
		buttonsPanel.add(saveButton);
		buttonsPanel.add(enableDisableButton);
		buttonsPanel.add(exportConfigButton);
		buttonsPanel.add(loadConfigButton);
		
		this.add(buttonsPanel);
				

	}
	
	public void Init()
	{		
		this.maxSessionsTextField.setText("100");
		this.tokenNameTextField.setText("TOKEN");
		this.sessionIDTextField.setText("SESSIONID");
		this.tokenResponseRegexTextField.setText("TOKEN\".*?value=\"(.*?)\".*?>");
		this.tokenMatchGroupTextField.setText("1");
		
	}
	

	public CSurferConfigurations GetConfigurations() {
		CSurferConfigurations currentConfigurations = new CSurferConfigurations();
		
		currentConfigurations.ANTI_CSRF_RESPONSE_REGEX = this.tokenResponseRegexTextField.getText();
		currentConfigurations.ANTI_CSRF_RESPONSE_REGEX_MATCH_GROUP = Integer.parseInt(this.tokenMatchGroupTextField.getText());
		currentConfigurations.ANTI_CSRF_TOKEN_NAME = this.tokenNameTextField.getText();
		currentConfigurations.MAX_NUM_SESSIONS = Integer.parseInt(this.maxSessionsTextField.getText());
		currentConfigurations.SESSION_ID_NAME = this.sessionIDTextField.getText();
		
		
		return currentConfigurations;
		
	}

}
