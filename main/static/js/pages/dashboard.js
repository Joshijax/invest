//[Dashboard Javascript]

//Project:	Unique Admin - Responsive Admin Template
//Primary use:   Used only for the main dashboard (index.html)


$(function () {

  'use strict';
	
	/*--- Sparkline charts - mini charts ---*/ 
		function sparkline_charts() {
			$('.sparklines').sparkline('html');
		}
		if ($('.sparklines').length) {
			sparkline_charts();
		} 
	
	if ($('.buyorder').length) {
        setRandomClass();
        setInterval(function () {
            setRandomClass();
        },1000);
        function setRandomClass() {
            var tbody = $(".buyorder table tbody");
            var items = tbody.find("tr");
            var number = items.length;
            var random1 = Math.floor((Math.random() * number));
            var random2 = Math.floor((Math.random() * number));
            items.removeClass("text-warning");
            items.eq(random1).addClass("text-warning");
            items.eq(random2).addClass("text-warning");
        }
    }
	
	if ($('.sellorder').length) {
        setRandomClass();
        setInterval(function () {
            setRandomClass();
        },1000);
        function setRandomClass() {
            var tbody = $(".sellorder table tbody");
            var items = tbody.find("tr");
            var number = items.length;
            var random1 = Math.floor((Math.random() * number));
            var random2 = Math.floor((Math.random() * number));
            items.removeClass("text-danger");
            items.eq(random1).addClass("text-danger");
            items.eq(random2).addClass("text-danger");
        }
    }

  //-----amchart
	//----------------chartdiv1

	var chart = AmCharts.makeChart( "chartdiv1", {
	  "type": "stock",
	"theme": "black",

	  //"color": "#fff",
	  "dataSets": [ {
		"title": "MSFT",
		"fieldMappings": [ {
		  "fromField": "Open",
		  "toField": "open"
		}, {
		  "fromField": "High",
		  "toField": "high"
		}, {
		  "fromField": "Low",
		  "toField": "low"
		}, {
		  "fromField": "Close",
		  "toField": "close"
		}, {
		  "fromField": "Volume",
		  "toField": "volume"
		} ],
		"compared": false,
		"categoryField": "Date",

		/**
		 * data loader for data set data
		 */
		"dataLoader": {
		  "url": "https://www.amcharts.com/wp-content/uploads/assets/stock/MSFT.csv",
		  "format": "csv",
		  "showCurtain": true,
		  "showErrors": true,
		  "async": true,
		  "reverse": true,
		  "delimiter": ",",
		  "useColumnNames": true
		},

		/**
		 * data loader for events data
		 */
		"eventDataLoader": {
		  "url": "https://www.amcharts.com/wp-content/uploads/assets/stock/MSFT_events.csv",
		  "format": "csv",
		  "showCurtain": true,
		  "showErrors": true,
		  "async": true,
		  "reverse": true,
		  "delimiter": ",",
		  "useColumnNames": true,
		  "postProcess": function( data ) {
			for ( var x in data ) {
			  switch ( data[ x ].Type ) {
				case 'A':
				  var color = "#85CDE6";
				  break;
				default:
				  var color = "#cccccc";
				  break;
			  }
			  data[ x ].Description = data[ x ].Description.replace( "Upgrade", "<strong style=\"color: #0c0\">Upgrade</strong>" ).replace( "Downgrade", "<strong style=\"color: #c00\">Downgrade</strong>" );
			  data[ x ] = {
				"type": "pin",
				"graph": "g1",
				"backgroundColor": color,
				"date": data[ x ].Date,
				"text": data[ x ].Type,
				"description": "<strong>" + data[ x ].Title + "</strong><br />" + data[ x ].Description
			  };
			}
			return data;
		  }
		}

	  }, {
		"title": "TXN",
		"fieldMappings": [ {
		  "fromField": "Open",
		  "toField": "open"
		}, {
		  "fromField": "High",
		  "toField": "high"
		}, {
		  "fromField": "Low",
		  "toField": "low"
		}, {
		  "fromField": "Close",
		  "toField": "close"
		}, {
		  "fromField": "Volume",
		  "toField": "volume"
		} ],
		"compared": true,
		"categoryField": "Date",
		"dataLoader": {
		  "url": "https://www.amcharts.com/wp-content/uploads/assets/stock/TXN.csv",
		  "format": "csv",
		  "showCurtain": true,
		  "showErrors": true,
		  "async": true,
		  "reverse": true,
		  "delimiter": ",",
		  "useColumnNames": true
		}
	  } ],
	  "dataDateFormat": "YYYY-MM-DD",

	  "panels": [ {
		  "title": "Value",
		  "percentHeight": 70,

		  "stockGraphs": [ {
			"type": "candlestick",
			"id": "g1",
			"openField": "open",
			"closeField": "close",
			"highField": "high",
			"lowField": "low",
			"valueField": "close",
			"lineColor": "#fff",
			"fillColors": "#fff",
			"negativeLineColor": "#db4c3c",
			"negativeFillColors": "#db4c3c",
			"fillAlphas": 1,
			"comparedGraphLineThickness": 2,
			"columnWidth": 0.7,
			"useDataSetColors": false,
			"comparable": true,
			"compareField": "close",
			"showBalloon": false,
			"proCandlesticks": true
		  } ],

		  "stockLegend": {
			"valueTextRegular": undefined,
			"periodValueTextComparing": "[[percents.value.close]]%"
		  }

		},

		{
		  "title": "Volume",
		  "percentHeight": 30,
		  "marginTop": 1,
		  "columnWidth": 0.6,
		  "showCategoryAxis": false,

		  "stockGraphs": [ {
			"valueField": "volume",
			"openField": "open",
			"type": "column",
			"showBalloon": false,
			"fillAlphas": 1,
			"lineColor": "#fbae1c",
			"fillColors": "#fbae1c",
			"negativeLineColor": "#db4c3c",
			"negativeFillColors": "#db4c3c",
			"useDataSetColors": false
		  } ],

		  "stockLegend": {
			"markerType": "none",
			"markerSize": 0,
			"labelText": "",
			"periodValueTextRegular": "[[value.close]]"
		  },

		  "valueAxes": [ {
			"usePrefixes": true
		  } ]
		}
	  ],

	  "panelsSettings": {
		//    "color": "#fff",
		"plotAreaFillColors": "#333",
		"plotAreaFillAlphas": 1,
		"marginLeft": 60,
		"marginTop": 5,
		"marginBottom": 5
	  },

	  "chartScrollbarSettings": {
		"graph": "g1",
		"graphType": "line",
		"usePeriod": "WW",
		"backgroundColor": "#333",
		"graphFillColor": "#666",
		"graphFillAlpha": 0.5,
		"gridColor": "#555",
		"gridAlpha": 1,
		"selectedBackgroundColor": "#444",
		"selectedGraphFillAlpha": 1
	  },

	  "categoryAxesSettings": {
		"equalSpacing": true,
		"gridColor": "#555",
		"gridAlpha": 1
	  },

	  "valueAxesSettings": {
		"gridColor": "#555",
		"gridAlpha": 1,
		"inside": false,
		"showLastLabel": true
	  },

	  "chartCursorSettings": {
		"pan": true,
		"valueLineEnabled": true,
		"valueLineBalloonEnabled": true
	  },

	  "legendSettings": {
		//"color": "#fff"
	  },

	  "stockEventsSettings": {
		"showAt": "high",
		"type": "pin"
	  },

	  "balloon": {
		"textAlign": "left",
		"offsetY": 10
	  },

	  "periodSelector": {
		"position": "bottom",
		"periods": [ {
			"period": "DD",
			"count": 10,
			"label": "10D"
		  }, {
			"period": "MM",
			"count": 1,
			"label": "1M"
		  }, {
			"period": "MM",
			"count": 6,
			"label": "6M"
		  }, {
			"period": "YYYY",
			"count": 1,
			"label": "1Y"
		  }, {
			"period": "YYYY",
			"count": 2,
			"selected": true,
			"label": "2Y"
		  },
		  /* {
			   "period": "YTD",
			   "label": "YTD"
			 },*/
		  {
			"period": "MAX",
			"label": "MAX"
		  }
		]
	  }
	} );

var chart = AmCharts.makeChart("market-depth", {
  "type": "serial",
  "theme": "black",
  "dataLoader": {
    "url": "https://poloniex.com/public?command=returnOrderBook&currencyPair=BTC_ETH&depth=50",
    "format": "json",
    "reload": 30,
    "postProcess": function(data) {
      
      // Function to process (sort and calculate cummulative volume)
      function processData(list, type, desc) {
        
        // Convert to data points
        for(var i = 0; i < list.length; i++) {
          list[i] = {
            value: Number(list[i][0]),
            volume: Number(list[i][1]),
          }
        }
       
        // Sort list just in case
        list.sort(function(a, b) {
          if (a.value > b.value) {
            return 1;
          }
          else if (a.value < b.value) {
            return -1;
          }
          else {
            return 0;
          }
        });
        
        // Calculate cummulative volume
        if (desc) {
          for(var i = list.length - 1; i >= 0; i--) {
            if (i < (list.length - 1)) {
              list[i].totalvolume = list[i+1].totalvolume + list[i].volume;
            }
            else {
              list[i].totalvolume = list[i].volume;
            }
            var dp = {};
            dp["value"] = list[i].value;
            dp[type + "volume"] = list[i].volume;
            dp[type + "totalvolume"] = list[i].totalvolume;
            res.unshift(dp);
          }
        }
        else {
          for(var i = 0; i < list.length; i++) {
            if (i > 0) {
              list[i].totalvolume = list[i-1].totalvolume + list[i].volume;
            }
            else {
              list[i].totalvolume = list[i].volume;
            }
            var dp = {};
            dp["value"] = list[i].value;
            dp[type + "volume"] = list[i].volume;
            dp[type + "totalvolume"] = list[i].totalvolume;
            res.push(dp);
          }
        }
       
      }
      
      // Init
      var res = [];
      processData(data.bids, "bids", true);
      processData(data.asks, "asks", false);
      
      //console.log(res);
      return res;
    }
  },
  "graphs": [{
    "id": "bids",
    "fillAlphas": 0.1,
    "lineAlpha": 1,
    "lineThickness": 2,
    "lineColor": "#0f0",
    "type": "step",
    "valueField": "bidstotalvolume",
    "balloonFunction": balloon
  }, {
    "id": "asks",
    "fillAlphas": 0.1,
    "lineAlpha": 1,
    "lineThickness": 2,
    "lineColor": "#f00",
    "type": "step",
    "valueField": "askstotalvolume",
    "balloonFunction": balloon
  }, {
    "lineAlpha": 0,
    "fillAlphas": 0.2,
    "lineColor": "#000",
    "type": "column",
    "clustered": false,
    "valueField": "bidsvolume",
    "showBalloon": false
  }, {
    "lineAlpha": 0,
    "fillAlphas": 0.2,
    "lineColor": "#000",
    "type": "column",
    "clustered": false,
    "valueField": "asksvolume",
    "showBalloon": false
  }],
  "categoryField": "value",
  "chartCursor": {},
  "balloon": {
    "textAlign": "left"
  },
  "valueAxes": [{
    "title": "Volume"
  }],
  "categoryAxis": {
    "title": "Price (BTC/ETH)",
    "minHorizontalGap": 100,
    "startOnAxis": true,
    "showFirstLabel": false,
    "showLastLabel": false
  },
  "export": {
    "enabled": true
  }
});

function balloon(item, graph) {
  var txt;
  if (graph.id == "asks") {
    txt = "Ask: <strong>" + formatNumber(item.dataContext.value, graph.chart, 4) + "</strong><br />"
      + "Total volume: <strong>" + formatNumber(item.dataContext.askstotalvolume, graph.chart, 4) + "</strong><br />"
      + "Volume: <strong>" + formatNumber(item.dataContext.asksvolume, graph.chart, 4) + "</strong>";
  }
  else {
    txt = "Bid: <strong>" + formatNumber(item.dataContext.value, graph.chart, 4) + "</strong><br />"
      + "Total volume: <strong>" + formatNumber(item.dataContext.bidstotalvolume, graph.chart, 4) + "</strong><br />"
      + "Volume: <strong>" + formatNumber(item.dataContext.bidsvolume, graph.chart, 4) + "</strong>";
  }
  return txt;
}

function formatNumber(val, chart, precision) {
  return AmCharts.formatNumber(
    val, 
    {
      precision: precision ? precision : chart.precision, 
      decimalSeparator: chart.decimalSeparator,
      thousandsSeparator: chart.thousandsSeparator
    }
  );
}
	
	
	/*
     * Flot Interactive Chart
     * -----------------------
     */
    // We use an inline data source in the example, usually data would
    // be fetched from a server
    var data = [], totalPoints = 200

    function getRandomData() {

      if (data.length > 0)
        data = data.slice(1)

      // Do a random walk
      while (data.length < totalPoints) {

        var prev = data.length > 0 ? data[data.length - 1] : 50,
            y    = prev + Math.random() * 10 - 5

        if (y < 0) {
          y = 0
        } else if (y > 100) {
          y = 100
        }

        data.push(y)
      }

      // Zip the generated y values with the x values
      var res = []
      for (var i = 0; i < data.length; ++i) {
        res.push([i, data[i]])
      }

      return res
    }

    var interactive_plot = $.plot('#interactive', [getRandomData()], {
      grid: {
            color: "#AFAFAF"
            , hoverable: true
            , borderWidth: 0
            , backgroundColor: '#252525'
        },
      series: {
        shadowSize: 0, // Drawing is faster without shadows
        color     : '#fb9678'
      },
	  tooltip: true,
      lines : {
        fill : '#fb9678', //Converts the line chart to area chart
        color: '#fb9678'
      },
	  tooltipOpts: {
            content: "Visit: %y"
            , defaultTheme: false
        },
      yaxis : {
        min : 0,
        max : 100,
        show: true
      },
      xaxis : {
        show: true
      }
    })

    var updateInterval = 50 //Fetch data ever x milliseconds
    var realtime       = 'on' //If == to on then fetch data every x seconds. else stop fetching
    function update() {

      interactive_plot.setData([getRandomData()])

      // Since the axes don't change, we don't need to call plot.setupGrid()
      interactive_plot.draw()
      if (realtime === 'on')
        setTimeout(update, updateInterval)
    }

    //INITIALIZE REALTIME DATA FETCHING
    if (realtime === 'on') {
      update()
    }
    
    /*
     * END INTERACTIVE CHART
     */
	
	
	//-----amchart3
var chart = AmCharts.makeChart( "chartdiv3", {
  "type": "gauge",
  "theme": "black",
  "startDuration": 0.3,
  "marginTop": 25,
  "marginBottom": 5,
  "axes": [ {
    "axisAlpha": 0.3,
    "endAngle": 360,
    "endValue": 12,
    "minorTickInterval": 0.2,
    "showFirstLabel": false,
    "startAngle": 0,
    "axisThickness": 1,
    "valueInterval": 1
  } ],
  "arrows": [ {
    "radius": "50%",
    "innerRadius": 0,
    "clockWiseOnly": true,
    "nailRadius": 10,
    "nailAlpha": 1
  }, {
    "nailRadius": 0,
    "radius": "80%",
    "startWidth": 6,
    "innerRadius": 0,
    "clockWiseOnly": true
  }, {
    "color": "#CC0000",
    "nailRadius": 4,
    "startWidth": 3,
    "innerRadius": 0,
    "clockWiseOnly": true,
    "nailAlpha": 1
  } ],
  "export": {
    "enabled": true
  }
} );

// update each second
setInterval( updateClock, 1000 );

// update clock
function updateClock() {
  if(chart.arrows.length > 0){
    // get current date
    var date = new Date();
    var hours = date.getHours();
    var minutes = date.getMinutes();
    var seconds = date.getSeconds();

    if(chart.arrows[ 0 ].setValue){
      // set hours
      chart.arrows[ 0 ].setValue( hours + minutes / 60 );
      // set minutes
      chart.arrows[ 1 ].setValue( 12 * ( minutes + seconds / 60 ) / 60 );
      // set seconds
      chart.arrows[ 2 ].setValue( 12 * date.getSeconds() / 60 );
      }
  }
}	

}); // End of use strict