/*
		VaacS Vulnerability assignment and classification System
		ID3/C4.5 ServiceNow Implementation
		TVM 2.0
		Initial Completion: 3/12/18
		Update Log -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
		
		
		
		-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
        
		Author(s): Marcus Hansen		
*/

//Istanbul doesn't support Log_base_2 natively So we define it here
Math.log2 = Math.log2 || function(x){return Math.log(x)*Math.LOG2E;};


//Our data format, better to think of as a raw vulnerability training record
function Dataset() {
    this.members        = [];
    this.classification = "";
}

//Frequency for each unique attribute belonging to 'x' column. 
//Tracks the number of times that unique member appeared, and the different 
//classifiers it was associated with. Mostly used for Information Gain, and Entropy Calculations
function Frequency() {

    //Used for identifying the column type, e.g. ports, protocols, ip, ect.
    this.type = "";

    this.member;
    this.occurence   = 0;
    this.classifiers = {};
}

//Our Node for our tree
function Node() {

    //Our arrays for tracking frequency with the different columns
    this.ports                      = [];
    this.protocols                  = [];
    this.ipAdr                      = [];
    this.pluginID                   = [];
    this.desc                       = [];
	
    //Is this a node that we have found a single classifier? Or have reached maximum number of iterations?
    this.leafNode                   = false;
    this.stem                       = false;

    //The selected Attribute for this node that corresponds to all of it's data. e.g. All the data that contains
    //port 22. Further still, if the parent of this node was a protocol, this could be the node that is on port 22,
    //and has a parent node of TCP
    this.selectedAttribute          = "";
	this.type                       = "";

    //A handle to our raw data. This is queried upon for each split to segment the data
    //in accordance to the specific attribute that was branched upon
    this.subset                     = [];

    //The diversity of this node in relation to classifiers
    this.classifier                 = {};

    //This nodes children
    this.children                   = [];

    //A handle to our parent node. There will only ever be one parent, and the roots parent will always be null
    this.parent                     = null;

    this.classifierBreakdown        = "";
    this.childrenSysIds             = "";

    this.sysId                      = "";
}

//Create our root node, and acquire a handle to the GlideRecord object
var rootNode             = new Node();
var gr                   = new GlideRecord("u_vulnerability_data");

//Instantate a subset array to store our raw training data
var subset               = [];

//These are used for the base entropy calculation. That is, for each unique classifier, how many times does it appear in relation to the total numberOfClassifiers
//In such a way that the formula equals p(x_classifier) = x_classifier/totalNumOfClassifiers
var numberOfClassifiers  = 0;
var classificationRatios = {};

gr.addQuery("u_vuln_assignment_group", "!=", "NULL");
gr.addQuery("u_client_vulnerability", "=", "false");
gr.query();

//gs.info(gr.getRowCount());

var memberAssociations = {};

//gather our feature set
while (gr.next()) {
    
    //Assign object member to primitives so by-value copy occurs when pushing into node subset
    var affectedPort     = 0;
    if (gr.u_affected_port != 0) affectedPort = 0 + gr.u_affected_port;
    var desc             = "";
    var affectedProtocol = "";
    if (gr.u_affected_protocol != "") affectedProtocol = "" + gr.u_affected_protocol;
    var ip = ""+gr.u_affected_os; 
    if (gr.u_plugin_id.u_plugin_name != "") desc = "" + gr.u_plugin_id.u_plugin_name;

    //We want to make sure our strings are "rinsed", and purified. 
    //replace common punctuation, and special characters with blank characters. 
   

    //Push it all back into a singlestring to function as a single attribute    
    var name = "";
    for (var i = 0; i < desc.length; i++) name += desc[i];
    var pluginID         = 0  + gr.u_plugin_id.u_plugin_id;

    //Populate our dataset function/object/thingamajing/javascript is weird
    var dataset          = new Dataset();
    dataset.members.push(affectedPort);
    dataset.members.push(affectedProtocol);
    dataset.members.push(ip);
    dataset.members.push(pluginID);
    dataset.members.push(name);

    var classification     = "" + gr.u_vuln_assignment_group;
    //gs.info(classification);
    dataset.classification = classification;   
   
    //Objects are normally copied *by reference* in Javascript. This is a problem since the aforementioned object is in a local scope. 
    //So we use JSON to parse/stringify, and get a *by value* copy of the object to preserve it out of scope
    subset.push(JSON.parse(JSON.stringify(dataset)));

    //Find repeat classifiers for entropy calc purposes
    var keyFound = false;
    for (key in classificationRatios) {
        if (key == dataset.classification) {
            //gs.info(dataset.classification);
            keyFound = true;
            classificationRatios[key]++;
        }
    }
    
    //if new classifier, add it to dicitionary
    if (!keyFound) classificationRatios[dataset.classification] = 1;

    //increment total num of classifiers
    numberOfClassifiers++;
}

//Assign the initial training data subset to the rootnode
rootNode.subset = subset;
//gs.info('Second: ' + rootNode.subset[0].classification);

//Calculate target classification ratios
//Uses Shannon Entropy (E -p(classifier(i))*Log2(classifier(i)))
var classificationEnthropy = 0.0;
for (key in classificationRatios) {
    var val = classificationRatios[key] / numberOfClassifiers;
    classificationEnthropy += -val*Math.log2(val);
}

//Figure out Member frequencies for Information Gain, and Entropy Calculations
populateRootNode();
//Get our handle for our rootNode
var node = rootNode;


var attributeIGs = {};
var portsTotal = 0;
for (var i = 0; i < node.ports.length; i++) {
	portsTotal += node.ports[i].occurence;
}   
var pluginTotal = 0;
for (var i = 0; i < node.pluginID.length; i++) {
	pluginTotal += node.pluginID[i].occurence;
}
var ipTotal = 0;
for (var i = 0; i < node.ipAdr.length; i++) {
	ipTotal += node.ipAdr[i].occurence;
}
var protocolsTotal = 0;
for (var i = 0; i < node.protocols.length; i++) {
	protocolsTotal += node.protocols[i].occurence;
}    
var descTotal = 0;
for (var i = 0; i < node.desc.length; i++) {
	descTotal += node.desc[i].occurence;
}            
	
//Calculate our information gain for our attributes
attributeIGs[node.ports[0].type] = calculateInformationGain(node.ports, portsTotal);
attributeIGs[node.pluginID[0].type] = calculateInformationGain(node.pluginID, pluginTotal);
attributeIGs[node.ipAdr[0].type] = calculateInformationGain(node.ipAdr, ipTotal);
attributeIGs[node.protocols[0].type] = calculateInformationGain(node.protocols, protocolsTotal);
attributeIGs[node.desc[0].type] = calculateInformationGain(node.desc, descTotal);

var gr1 = new GlideRecord('u_vaacs_data');
gr1.deleteMultiple();

var arrList = [];
createTree(node, 0, JSON.parse(JSON.stringify(arrList)), null);

//Finally Create Our Decision Tree :^)
function createTree(node, iterations, arrList, parent) {

    var gr = new GlideRecord('u_vaacs_data');
    gr.initialize();
    gr.u_selected_attribute = "" + node.type + ":" + node.selectedAttribute;

    if (iterations > 2) gr.u_leaf_node = true;
    gr.u_leaf_node          = node.leafNode;
    if (parent != null) gr.u_parent_node        = parent.sysId;
    gr.u_iterations_deep    = iterations;
    gr.insert();

    if (iterations == 0) gr.u_node_id           = ""+"ROOT_NODE";
    else gr.u_node_id           = ""+gr.sys_id;
    gr.update(); 

    node.sysId = gr.sys_id;

    //If our iterations are greater then 3 (base-0) or, 
    //If the current node is a leaf node, stop growing this branch, and return

    var classifierBreakdown = "";
    if (iterations > 2 || node.leafNode) {
        var classifiers             = {};
        for (var j = node.subset.length-1; j >= 0; j--) {
            if (!(node.subset[j].classification in classifiers)) {
                classifiers[node.subset[j].classification] = 1;
            }
            else classifiers[node.subset[j].classification]++;
        }

        var clTotal = 0;
        for (var key in classifiers) {
            clTotal += classifiers[key];
        }

        for (var key in classifiers) {
			classifierBreakdown += ":";
            classifierBreakdown += "" + key + ":" + (classifiers[key]/clTotal*100);
        }

        gr.u_classifier_summary = classifierBreakdown;
        gr.update();

        if (iterations > 2) {
            if (!node.leafNode) {
			    gr.u_stem = true;
                gr.update();
		    }
        }
        return;
    }

    //find the highest IG from the attributes
    var hKey = "";
    var val = 0.0;
    for (key in attributeIGs) {
        //gs.info(attributeIGs[key]);

        var containsMatch = false;
        for (var i = 0; i < arrList.length; i++) {
            if (key == arrList[i]) {
                containsMatch = true;
            }
        }
        if (containsMatch) continue;

        if (attributeIGs[key] > val) {
            val = attributeIGs[key];
            hKey = key;
        }
    }
    

    gs.info(hKey);
    arrList.push(hKey);
    //depending on which attributes key was highest, split the tree based on that attribute
    switch (hKey) {
        case 'protocols':
            split(node, node.protocols, 'protocols');
            break;
        case 'ports':
            //gs.info('port split');
            split(node, node.ports, 'ports');
            break;
        case 'ipAdr':
            split(node, node.ipAdr, 'ipAdr');
            break;
        case 'pluginID':
            split(node, node.pluginID, 'pluginID');
            break;
        case 'desc':
            split(node, node.desc, 'desc');
            break;
    }

    var classTotal = 0;
    for (var key in node.classifier) {
         classTotal += node.classifier[key];
          gs.info(node.classifier[key]);
    }
    //gs.info(class Total);
    for (var key in node.classifier) {
	   classifierBreakdown += ":";
       classifierBreakdown += "" + key + ":" + (node.classifier[key]/classTotal*100);
    }

    gr.u_classifier_summary = classifierBreakdown;
    gr.update();

    var sattributeIGs = {};
   /* 
    gs.info("This Node has: " + node.children.length + " Children");
    for (var i = 0; i < node.children.length; i++) {
        gs.info("Selected Attribute: " + node.children[i].selectedAttribute);
        var classifiers = {};
        for (var j = 0; j < node.children[i].subset.length; j++) {
            var str = "";
            var ke  = "";
	    for (var k = 0; k < node.children[i].subset[j].members.length; k++) {
                str += node.children[i].subset[j].members[k];
                key = "" + node.children[i].subset[j].classification;
	    }
            gs.info("Child Subset : " + (str + ke));
        }
    }*/

    //Loop through the current nodes children, and recursively call this function to continue growing the
    //the branch
    //gs.info(node.children.length);
    
    for (var i = 0; i < node.children.length; i++) {
        createTree(node.children[i], iterations+1, JSON.parse(JSON.stringify(arrList)), node);
        gr.u_children_sys_ids += node.children[i].sysId;
		if (i+1 < node.children.length) gr.u_children_sys_ids += ":";
        gr.update();
    }
}

//Populate our rootNode. Find all unique attributes, and their features. This is used for the information
//gain formulas.
function populateRootNode() {
   
    for (var i = 0; i < subset.length; i++) {
        for (var j = 0; j < subset[i].members.length; j++) {
            var x = [];

            switch (j) {
                case 0:
				    //Find member occurences for 'x' (in this case ports), their unique attributes, and there classifier makeup
                    x = findMemberOccurences(rootNode.ports, subset[i].members[j], subset[i].classification);
                    if (x && x.length) rootNode.ports = x;
                    break;
                case 1:
                    x = findMemberOccurences(rootNode.protocols, subset[i].members[j], subset[i].classification);
                    if (x && x.length) rootNode.protocols = x;
                    break;
                case 2:
                    x = findMemberOccurences(rootNode.ipAdr, subset[i].members[j], subset[i].classification);
                    if (x && x.length) rootNode.ipAdr = x;
                    break;
                case 3:
                    x = findMemberOccurences(rootNode.pluginID, subset[i].members[j], subset[i].classification);
                    if (x && x.length) rootNode.pluginID = x;
                    break;
                case 4:
                    x = findMemberOccurences(rootNode.desc, subset[i].members[j], subset[i].classification);
                    if (x && x.length) rootNode.desc = x;
                    break;
                default:
                    gs.info("shit");
                    break;
            }
			
			//if 
            if (!x && !x.length) {
               var frequency                                                       = new Frequency();
               frequency.member                                                    = subset[i].members[j];
               frequency.occurence                                                 = 1;
               frequency.classifiers[subset[i].classification]                     = 1;
               switch (j) {
                   case 0:
                       frequency.type = "ports";
                       rootNode.ports.push(JSON.parse(JSON.stringify(frequency)));
                       break;
                   case 1:
                       frequency.type = "protocols";
                       rootNode.protocols.push(JSON.parse(JSON.stringify(frequency)));
                       break;
                   case 2:
                       frequency.type = "ipAdr";
                       rootNode.ipAdr.push(JSON.parse(JSON.stringify(frequency)));
                       break;
                   case 3:
                       frequency.type = "pluginID";
                       rootNode.pluginID.push(JSON.parse(JSON.stringify(frequency)));
                       break;
                   case 4:
                       frequency.type = "desc";
                       rootNode.desc.push(JSON.parse(JSON.stringify(frequency)));
                       break;
                   default:
                       gs.info("shit");
                       break;
                }
            }
        }
    }
}

function split(node, x, type) {
    for (var i = 0; i < x.length; i++) {
        child = new Node();
        var attributeFoundInDataset = false;
        var classifiers             = {};
        for (var j = node.subset.length-1; j >= 0; j--) {
				switch (type) {
					case 'protocols':
						if (x[i].member == node.subset[j].members[1]) {
							child.subset.push(JSON.parse(JSON.stringify(node.subset[j])));
                                                        if (!(node.subset[j].classification in child.classifier)) child.classifier[node.subset[j].classification] = 1;
                                                        else child.classifier[node.subset[j].classification]++;
							child.selectedAttribute                                             = x[i].member;
							child.type = "u_affected_protocol";
							node.subset.splice(j, 1);
							attributeFoundInDataset = true;
						}
						break;
					case 'ports':
					        if (x[i].member == node.subset[j].members[0]) {
							child.subset.push(JSON.parse(JSON.stringify(node.subset[j])));
                                                        if (!(node.subset[j].classification in child.classifier)) child.classifier[node.subset[j].classification] = 1;
                                                        else child.classifier[node.subset[j].classification]++;
							child.selectedAttribute                                             = x[i].member;
							child.type = "u_affected_port";
							node.subset.splice(j, 1);
							attributeFoundInDataset = true;
						}
						break;
					case 'ipAdr':
					    if (x[i].member == node.subset[j].members[2]) {
							child.subset.push(JSON.parse(JSON.stringify(node.subset[j])));
                                                        if (!(node.subset[j].classification in child.classifier)) child.classifier[node.subset[j].classification] = 1;
                                                        else child.classifier[node.subset[j].classification]++;
							child.selectedAttribute                                             = x[i].member;
							child.type = "u_affected_os";
							node.subset.splice(j, 1);
							attributeFoundInDataset = true;
						}
						break;
					case 'pluginID':
					    if (x[i].member == node.subset[j].members[3]) {
							child.subset.push(JSON.parse(JSON.stringify(node.subset[j])));
                                                        if (!(node.subset[j].classification in child.classifier)) child.classifier[node.subset[j].classification] = 1;
                                                        else child.classifier[node.subset[j].classification]++;
							child.selectedAttribute                                             = x[i].member;
							child.type = "u_plugin_id.u_plugin_id";
							node.subset.splice(j, 1);
							attributeFoundInDataset = true;
						}
						break;
					case 'desc':
					    if (x[i].member == node.subset[j].members[4]) {
							child.subset.push(JSON.parse(JSON.stringify(node.subset[j])));
                                                        if (!(node.subset[j].classification in child.classifier)) child.classifier[node.subset[j].classification] = 1;
                                                        else child.classifier[node.subset[j].classification]++;
							child.selectedAttribute                                             = x[i].member;
							child.type = "u_plugin_id.u_plugin_name";
							node.subset.splice(j, 1);
							attributeFoundInDataset = true;
						}
					    break;
				}
			
		}
		if (attributeFoundInDataset) {

                        //This attribute possesses only one classifier making it a leaf node. The branching stops with this node.
                        if (Object.keys(child.classifier).length == 1) {
                            child.leafNode = true;
                        }

			node.children.push(JSON.parse(JSON.stringify(child)));
			node.children[node.children.length-1].ports = node.ports;
			node.children[node.children.length-1].ipAdr = node.ipAdr;
                        node.children[node.children.length-1].protocols = node.protocols;
                        node.children[node.children.length-1].pluginID = node.pluginID;
                        node.children[node.children.length-1].desc = node.desc;
		}
	}      
}

function findMemberOccurences(x, y, z) {

    var matchedMember = false;
    for (var i = 0; i < x.length; i++) {
        if (x[i].member == y) {
            x[i].occurence++;
                   
            var keyFound = false;
            for (key in x[i].classifiers) {
                if (key == z) {
                    x[i].classifiers[z]++
                    keyFound = true;
                }
            }  
                   
            if (!keyFound) x[i].classifiers[z] = 1;
            matchedMember     = true;
            break;
        }
    }
    
    if (!matchedMember) x = [];
    return x;
}

function calculateInformationGain(x, x_maxlength) {
    var classificationEnthropies = [];
    var IG = 0.0;
    for (var i = 0; i < x.length; i++) {
        var enthropy = 0.0;
        for (key in x[i].classifiers) {
            var val = x[i].classifiers[key] / x[i].occurence;
            enthropy -= val*Math.log2(val);
        }
        classificationEnthropies.push(enthropy);
    }

    IG = classificationEnthropy;

    var val = 0.0;
    for (var i = 0; i < x.length; i++) {4
        val -= (x[i].occurence / x_maxlength)*classificationEnthropies[i];      
    }
    //gs.info(val);
    IG -= val;
    return IG;
}