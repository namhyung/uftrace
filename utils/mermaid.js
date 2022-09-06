const GRAPH_TITLE = new String("graph TB\n");
const FULL_DEPTH = document.getElementById("depth-select").options[0];
const COMMENT = new String("%% ");
const FUNC_ID_PATTERN = /(?<node_depth>\d+)_(?<node_id>\d+)/;
const COLOR_SUB_DEPTH = new String("#f9f");
const COLOR_PARTIAL_GRAPH = new String("#cab8ff");
const COLOR_STROKE = new String("#333");
let startId = new Array();
let startDepth = new Array();
let startName = new Array();
let callFlow = new Array();
let openNode = new Array();
let baseRootName = new String();
let baseRootId = new String("0");
let baseGraph = new String();
let baseRootDepth = new Number(FULL_DEPTH);
let showHideDesc = new String();
let maxDepth = new Number(1);

const mermaidTxt = document.getElementById("meraid_graph").innerHTML;

var showHideNode = function(nodeId) {
	const nodeIdResult = nodeId.match(FUNC_ID_PATTERN);
	if (nodeIdResult == null) {
		document.getElementById("description").innerHTML = "Invalid Node ID : " + nodeId;
		return;
	}
	const id = nodeIdResult.groups.node_id;
	const depth = nodeIdResult.groups.node_depth;
	const open = openNode.includes(id);
	let start = new Boolean(false);
	for (let i = 0; i < callFlow.length; i++) {
		if (start == false && Number(startId[i]) == id) {
			start = true;
		}
		if (start == true) {
			if (Number(startId[i]) == id || startDepth[i] > depth) {
				if (open)
					callFlow[i] = COMMENT + callFlow[i];
				else
					callFlow[i] = callFlow[i].replace(COMMENT, "");
			}
			else {
				break;
			}
		}
	}
	if (open)
		openNode.pop(id);
	else
		openNode.push(id);

	renderGraph("".concat(GRAPH_TITLE, callFlow.join("\n"), "\n", showHideDesc));
};

var selectSubGraph = function(nodeId) {
	const nodeIdResult = nodeId.match(FUNC_ID_PATTERN);
	const id = nodeIdResult.groups.node_id;

	for (let i = 0; i < callFlow.length; i++) {
		if (Number(startId[i]) == id) {
			drawBaseGraph(id);
			break;
		}
	}
};

var initializeBaseGraph = function() {
	startId.length = 0;
	startDepth.length = 0;
	startName.length = 0;
	openNode.length = 0;
	callFlow.length = 0;
	showHideDesc = "";
	baseGraph = "";
};

var getNodeStyle = function(id, fillColor, strokeColor) {
	return "  style " + id + " fill:" + fillColor + " ,stroke:" + strokeColor +
	       ",stroke-width:px;";
};

var drawDepthGraph = function(depth) {
	mermaid.initialize(config);
	showHideDesc = "";
	openNode.length = 0;
	const nodeList = new Array();
	let id = new String();
	for (let i = 0; i < callFlow.length; i++) {
		callFlow[i] = callFlow[i].replace(COMMENT, "");
		if (Number(startDepth[i]) >= depth)
			callFlow[i] = (COMMENT + callFlow[i]);
		if (Number(startDepth[i]) == depth) {
			id = startDepth[i] + "_" + startId[i];
			if (nodeList.includes(id) == false) {
				nodeList.push(id);
				showHideDesc = showHideDesc.concat(
					getNodeStyle(id, COLOR_SUB_DEPTH, COLOR_STROKE), "\n");
				showHideDesc =
					showHideDesc.concat("  click " + id + " showHideNode;\n");
			}
		}
	}
	renderGraph("".concat(GRAPH_TITLE, callFlow.join("\n"), "\n", showHideDesc));
};

function drawSelectGraph()
{
	let selectionDesc = new String();
	let nodeList = new Array();
	if (callFlow.length == 0)
		drawBaseGraph(0);
	for (let i = 1; i < callFlow.length; i++) {
		let id = startDepth[i] + "_" + startId[i];
		if (nodeList.includes(id) == false) {
			nodeList.push(id);
			selectionDesc = selectionDesc.concat(
				getNodeStyle(id, COLOR_PARTIAL_GRAPH, COLOR_STROKE), "\n");
			selectionDesc =
				selectionDesc.concat("  click " + id + " selectSubGraph;\n");
		}
	}
	renderGraph(baseGraph.concat("\n", selectionDesc));
	document.getElementById("description").innerHTML = "Click on a node to view Sub-Graph";
};

var drawBaseGraph = function(id) {
	mermaid.initialize(config);
	initializeBaseGraph();
	let start = new Boolean(false);
	maxDepth = 0;
	var result = mermaidTxt.split(/\r?\n/);
	for (let i = 0; i < result.length; i++) {
		if (result[i].length == 0)
			continue;
		let oneCallFlow = result[i].match(
			/\s+(?<start_depth>\d+)_(?<start_id>\d+)\[\"(?<start_name>\S+)\"\]\s+--\S+\|(?<call_num>\d+)\|\s+(?<end_depth>\d+)_(?<end_id>\d+)\[\"(?<end_name>\S+)\"];/);
		// If call flow is
		// 	3_6["A"] -->|2| 4_9["B"];
		// , each matching value is like
		// 	start_depth : 3, start_id : 6, start_name : A, call_num : 2, end_depth : 4, end_id : 9, end_name : B

		if (oneCallFlow == null)
			continue;
		if (Number(oneCallFlow.groups.start_id) == id) {
			start = true;
			baseRootDepth = Number(oneCallFlow.groups.start_depth);
			baseRootId = id;
		}
		if (start == true) {
			if (Number(oneCallFlow.groups.start_depth) > baseRootDepth ||
			    Number(oneCallFlow.groups.start_id == id)) {
				callFlow.push(result[i]);
				startId.push(oneCallFlow.groups.start_id);
				startDepth.push(oneCallFlow.groups.start_depth);
				startName.push(oneCallFlow.groups.start_name);
			}
			else {
				break;
			}
		}
		if (Number(oneCallFlow.groups.start_depth) > maxDepth)
			maxDepth = Number(oneCallFlow.groups.start_depth);
	}
	baseGraph = "".concat(GRAPH_TITLE, callFlow.join("\n"));
	updateDepthList();
	renderGraph(baseGraph);
};

var updateDepthList =
	function() {
	var select = document.getElementById("depth-select");
	select.options.length = 0;
	select.options[0] = new Option("Full", FULL_DEPTH);
	let limit = new Number(maxDepth - Number(baseRootDepth) + 1);
	for (let i = 1; i <= limit; i++) {
		select.options[select.options.length] = new Option(i, i);
	}
}

var renderGraph = function(graphText) {
	var graphDiv = document.getElementById("meraid_graph");
	graphText = graphText.replace(/&gt;/g, ">");
	var insertSvg = function(svgCode, bindFunctions) {
		graphDiv.innerHTML = svgCode;
		if (typeof callback != "undefined") {
			callback(id);
		}
		bindFunctions(graphDiv);
	};
	mermaid.render("callGraph", graphText, insertSvg, graphDiv);
	document.getElementById("description").innerHTML = "";
};

let selector = document.getElementById("depth-select");
selector.addEventListener("click", () => {
	selector.addEventListener("change", () => {
		if (callFlow.length == 0)
			drawBaseGraph(0);
		showHideDepth = Number(document.getElementById("depth-select").value) +
				Number(baseRootDepth);
		if (showHideDepth != FULL_DEPTH)
			drawDepthGraph(showHideDepth);
	});
});
