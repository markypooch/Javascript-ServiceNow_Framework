function NSXRESTCall(endPoint, method, ipSetXML, eTag, acceptType, contentType) {
	var restMessage = new sn_ws.RESTMessageV2();
	restMessage.setEndpoint(endPoint);
	restMessage.setHttpMethod(method);  
	restMessage.setMIDServer(gs.getProperty('x_ibmfi_ibm_automa.mid_server'));  
	restMessage.setRequestHeader("content-type", contentType);  
	restMessage.setRequestHeader("accept", acceptType);
	restMessage.setRequestHeader("Authorization", "Basic " + gs.getProperty('x_ibmfi_ibm_automa.nsx_manager_cred'));
	restMessage.setEccParameter('skip_sensor', true);
	
	if (eTag != "") {
		restMessage.setRequestHeader("If-Match", eTag);
	}
	if (method == "POST") restMessage.setRequestBody(ipSetXML);
	
	var response        = restMessage.executeAsync(); 
	gs.info(response.getStatusCode());
    return response;
}

try
{
	var endPoint = 'https://' + gs.getProperty('x_ibmfi_ibm_automa.nsx_manager_bdr') + '/api/4.0/edges';
	var response = NSXRESTCall(endPoint, "GET", "", "", "application/json", "application/json");

	if (response.getStatusCode() == 200) {
		var xmlPayload = JSON.parse(response.getBody());
		for (var i = 0; i < xmlPayload.edgePage.data.length; i++) {
			var string = xmlPayload.edgePage.data[i].name;
			if (string.indexOf('ESG') != -1) {
					var gr = new GlideRecord('x_ibmfi_ibm_automa_nsx_firewalls');
					gr.addQuery('name', 'CONTAINS', string);
					gr.query();
				
					if (!gr.hasNext()) {
				
						var companyPrefix = xmlPayload.edgePage.data[i].name.substring(1, 3);

						var location = new GlideRecord("cmn_location");
						location.addQuery('name', '=', 'IBM Boulder');
						location.query();

						var location_sysid = '';
						if (location.next()) {
							location_sysid = location.sys_id;
						}

						var ci_gr = new GlideRecord('cmdb_ci_firewall_network');
						ci_gr.initialize();
						ci_gr.name      = xmlPayload.edgePage.data[i].name;
						ci_gr.asset_tag = xmlPayload.edgePage.data[i].nodeId;
						ci_gr.device_type = "firewall";
						ci_gr.description = companyPrefix + " NSX Virtual Firewall. Hosted at IBM Boulder.";
						ci_gr.firmware_version = xmlPayload.edgePage.data[i].apiVersion;
						ci_gr.location    = location_sysid;
						ci_gr.insert();

						var gr = new GlideRecord('x_ibmfi_ibm_automa_nsx_firewalls');
						gr.initialize();
						gr.name         = xmlPayload.edgePage.data[i].name;
						gr.vsmuuid      = xmlPayload.edgePage.data[i].vsmUuid;
						gr.node_id      = xmlPayload.edgePage.data[i].nodeId;
						gr.revision     = xmlPayload.edgePage.data[i].revision;
						gr.is_universal = xmlPayload.edgePage.data[i].isUniversal;
						gr.id           = xmlPayload.edgePage.data[i].id;
						gr.state        = xmlPayload.edgePage.data[i].state;
						gr.edge_status  = xmlPayload.edgePage.data[i].edgeStatus;
						gr.firewall_ci  = ci_gr.sys_id;
						gr.insert();
					}
				
			}
		}
	}
	
	
	//restMessage.setEndpoint('https://' + gs.getProperty('x_ibmfi_ibm_firewa.nsx_manager_bdr') + '/api/4.0/firewall/globalroot-0/config/layer3sections/1/rules/1013');
	endPoint = 'https://' + gs.getProperty('x_ibmfi_ibm_automa.nsx_manager_bdr') + '/api/4.0/firewall/globalroot-0/config';
	
	response = NSXRESTCall(endPoint, "GET", "", "", "application/json", "application/json");
    if (response.getStatusCode() == 200) {

		var jSon = JSON.parse(response.getBody());
		for (var j = 0; j < jSon.layer3Sections.layer3Sections.length; j++) {
				var gr = new GlideRecord('x_ibmfi_ibm_automa_nsx_firewall_section');
				gr.addQuery('name', 'CONTAINS', ('Boulder ' + jSon.layer3Sections.layer3Sections[j].name));
				gr.query();
				if (!gr.hasNext()) {
			
					var gr = new GlideRecord('x_ibmfi_ibm_automa_nsx_firewall_section');
					gr.initialize();
					gr.name = 'Boulder ' + jSon.layer3Sections.layer3Sections[j].name;
					gr.section_value   = jSon.layer3Sections.layer3Sections[j].id;
					gr.update();
				}
		}
	}
}
catch (err) {
	gs.info("MPH IBM Firewall: " + err.message);
}