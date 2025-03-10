from PIL import Image, ImageDraw, ImageOps
from PIL import ImageFont
from datetime import datetime
import os
from urllib.parse import urlsplit
from io import BytesIO


class poc():

	def __init__(self):
		self._terminalPrompt = "root@nuclei-scanner: "
		self.fqdn, self.macAddr = None, None


	def generatePoc(self, finding, markPoints=[], colorType=None , pocType=None):
		"""
		Generate Image from Scan Output and adds markpoint to the PoC.

		Args:
		  finding: String Scan Output
		  markPoints: List of string to mark in PoC (Default value = [])
		  pocType: (Optional) Only used to generate request response PoC. (Default value = None)
		  colorType: Used to set backgroud color of PoC Image, Currently onyly supports Black & White. (Default value = None)
		"""

		fontSize = 16       	# font size to use in PoC
		newLineSpacing = 6  	# space between two new lines in pixels
		findingLength = len(finding.split("\n")) + 1                     # length of image according to number of lines in findings
		findingLength = findingLength * (fontSize + newLineSpacing)      # define length of image, 22pixels for every new line
		imageWidth = 800  	 	# defines width of PoC image
		pocMargin = 10      	# text starting X & Y axis
		markGap = 3         	# for setting top mark difference between 2 lines.
		flag = 0           		# counter to count Linr to mark number
		lineNumber = set()     	# list of line numbers to mark

		if colorType is not None:
			if colorType == "white":
				color = [(255,255,255), (0,0,0)]
		else:
			color = [(0,0,0), (255,255,255)]

		img = Image.new("RGB", (imageWidth, findingLength), color=color[0]) # 73, 109, 137
		textImg = ImageDraw.Draw(img)
		font = ImageFont.truetype(font=f"{os.path.dirname(__file__)}/static/font.ttf", size=fontSize)
		fontSizePx = font.getsize(finding[1])[1]

		textImg.text(
			(10, 10), 
			finding, 
			spacing=newLineSpacing, 
			fill = color[1], 
			font=font
		)

		if markPoints:
			for line in finding.split("\n"):
				for mark in markPoints:
					if mark in line:
						lineNumber.add(flag)
				flag = flag + 1

			if len(lineNumber) > 0:
				lineNumber = self.groupSequence(list(lineNumber))

				for lines in lineNumber:
					markTop = pocMargin + (newLineSpacing+fontSizePx) * (lines[0]) - markGap
					markBottom = pocMargin + (newLineSpacing+fontSizePx) * (lines[-1]) + fontSizePx + markGap
					textImg.rectangle(((pocMargin-3, markTop), (imageWidth-10, markBottom)), outline="green")

		if pocType == "REQUEST_RESPONSE":
			return img

		buffer = BytesIO()
		img.save(buffer, format="jpeg")
		
		return buffer


	def formatPoc(self, finding, port=""):
		"""Adds Hostname, Time & Port Number in PoC.

		Args:
		  finding String Scan Output.
		  port String Port Number. (Default value = "")
		"""

		time = datetime.now().strftime(r"%b %d %Y %H:%M:%S %Z")
		header = str()

		if port:
			header = f"Host: {self.host} \t Port: {port}\n"
		else:
			header = f"Host: {self.host}\n"
		
		if self.macAddr:
			header = f"{header}MAC: {self.macAddr}\t\t"

		if self.fqdn:
			header = f"{header}Hostname: {self.fqdn}\n\n"

		finding = f"{header}{time}\n\n{finding}"

		return finding


	def groupSequence(self, markPoints):
		"""
		Combiness the markpoint in PoC,
		If there is more than 1 continuous line that require marking.

		Args:
		  markPoints: List of linu number to mark.
		"""
		markPoints.sort()
		
		sequence = [[markPoints[0]]]

		for i in range(1, len(markPoints)):

			if markPoints[i-1]+1 == markPoints[i]:
				sequence[-1].append(markPoints[i])
			else:
				sequence.append([markPoints[i]])

		return sequence


	def getMarkpoints(self, scanResult):
		markPoints = list()
		
		if not scanResult["matcher-status"] or scanResult.get("extracted-results") or scanResult.get("vuln-meta"):
			return markPoints
		else:
			if scanResult.get("matcher-name"):
				markPoints.append(scanResult["matcher-name"])

			if scanResult.get("extracted-results"):
				markPoints.append(scanResult["extracted-results"])

			if scanResult.get("vuln-meta"):
				for _, value in scanResult["vuln-meta"].items():
					if value:
						markPoints.append(value)

		return markPoints
	

	def createPoc(self, scanResult:dict, markPoints:list=[]):
		"""Use this function to generate shell based PoC.

		Args:
		  scanResult : String Scan Output.
		  markPoints(optional) : List Keywords to mark in PoC(Keywords are case sensitive). (Default value = [])
		  port(optional) : String Port number of finding to add in PoC. (Default value = "")

		Returns:
			Example: _poc.createPoc(scanOutput, markPoints=["Vulnerable"], port="443")
		"""

		if not markPoints:
			markPoints = self.getMarkpoints(scanResult)
		
		if scanResult["type"] == "http":
			self.requestResponsePoc(scanResult, markPoints)

		host, command, port = ""

		scanResult = self.formatPoc(host, command, scanResult, port=str(port))
		return self.generatePoc(scanResult, markPoints)
	

	def concatImage(self, requestImg, responseImg):
		"""
		Concats Request PoC and Response PoC to generate REQUEST_RESPONSE PoC.

		Args:
		  requestImg: request PoC image object.
		  responseImg: response PoC image object.

		Returns: returnImage object

		"""

		imgWidth = requestImg.width + responseImg.width + 10

		if requestImg.height > responseImg.height:
			imgHeight = requestImg.height
		else:
			imgHeight = responseImg.height

		img = Image.new("RGB", (imgWidth, imgHeight), color = (255, 255, 255))

		img.paste(requestImg, (0, 0))
		img.paste(responseImg, (requestImg.width + 10, 0))

		img1 = ImageDraw.Draw(img)
		img1.line([(requestImg.width, 0),(requestImg.width, imgHeight)], fill =(0, 0, 0), width = 5)

		return img


	def parseResponseText(self, responseText, markpoints):
		"""
		Args:
		  responseText:
		  markpoint

		Returns: PoC String
		"""
		if responseText:
			lineNumber1 = list(range(-5, 6))
			lineNumber = list(range(0, 11))

			responseText = ">\n<".join(responseText.split("><"))
			responseList = responseText.split("\n")

			num = 0
			line = 0
			if markpoints:
				for text in responseList:
					for markpoint in markpoints:
						if markpoint in text:
							line = num
							break
					num+=1

					if line != 0:
						break

			if line != 0:
				lineNumber = lineNumber1

			tempStr = ""
			if len(responseList) >= 11:
				for index in lineNumber:
					tempStr += responseList[line+index] + "\n"
			else:
				for resp in responseList:
					tempStr += resp + "\n"
		else:
			tempStr = ""

		return tempStr


	def requestResponsePoc(self, scanResult:dict, markPoints:list=[]) -> object:
		"""
		Use this function to generate burpsuite like Request & Response based PoC.

		Args:
		  scanResult : nuclei scan result object.
		  markPoints(optional) : List Keywords to mark in PoC(Keywords are case sensitive). (Default value = [])

		Returns:
		  object : PoC image

		Example: _poc.requestResponsePoc(responseObject, markPoints=["TRACE","DEBUG"])
		"""

		requestImg = self.generatePoc(
			scanResult["request"], 
			markPoints=markPoints, 
			colorType="white", 
			pocType="REQUEST_RESPONSE"
		)

		responseImg = self.generatePoc(
			self.parseResponseText(scanResult["response"], markPoints), 
			markPoints=markPoints, 
			colorType="white", 
			pocType="REQUEST_RESPONSE"
		)

		mergedImg = self.concatImage(requestImg, responseImg)
		ImageOps.expand(mergedImg, border=1, fill="black")

		buffer = BytesIO()
		mergedImg.save(buffer, format="jpeg")

		return buffer
