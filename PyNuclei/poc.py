import os
import textwrap
from PIL import Image, ImageDraw, ImageOps
from PIL import ImageFont


class poc():

	@staticmethod
	def generatePoc(finding, markPoints=[], colorType=None , pocType=None):
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
				lineNumber = poc.groupSequence(list(lineNumber))

				for lines in lineNumber:
					markTop = pocMargin + (newLineSpacing+fontSizePx) * (lines[0]) - markGap
					markBottom = pocMargin + (newLineSpacing+fontSizePx) * (lines[-1]) + fontSizePx + markGap
					textImg.rectangle(((pocMargin-3, markTop), (imageWidth-10, markBottom)), outline="red")

		return img


	@staticmethod
	def formatTerminalPoc(scanResult):
		"""
		Adds Hostname, Time & Port Number in PoC.

		Args:
		  scanResult: Scan Output.
		"""
		command = f"root@nuclei~scanner#: nuclei -target {scanResult['host']} -t {scanResult['template-id']}\n"
		port = scanResult.get("port")
		host = scanResult.get("host")
		if port:
			host = host.split(f":{port}")[0]

		# time = datetime.now().strftime(r"%b %d %Y %H:%M:%S %Z")
		# header = str()

		# if port:
		# 	header = f"Host: {host} \t Port: {port}\n"
		# else:
		# 	header = f"Host: {host}\n"
		
		# if macAddr:
		# 	header = f"{header}MAC: {macAddr}\t\t"
		# if fqdn:
		# 	header = f"{header}Hostname: {fqdn}\n\n"

		return f"{command}\nIssue Name: {scanResult.get('issue-name')}\nProtocol: {scanResult.get('type')}\nResponse: {scanResult.get('response')}\nMatched-At: {scanResult.get('matched-at')}\nExtracted-Results: {scanResult.get('extracted-results')}"
	

	@staticmethod
	def groupSequence(markPoints):
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


	@staticmethod
	def wordWrapCode(codeString, width=100):
		"""
		Wraps a long code string into multiple lines with a specified width.

		Args:
			code_string (str): The long code string to wrap.
			width (int): The maximum width of each line (default: 80).

		Returns:
			str: The wrapped code string.
		"""

		wrappedLines = []
		lines = codeString.splitlines()  # Split into individual lines

		for line in lines:
			wrappedLines.extend(textwrap.wrap(line, width=width)) # wrap each line

		return "\n".join(wrappedLines)
	

	@staticmethod
	def getMarkpoints(scanResult):
		markPoints = list()
		
		if scanResult.get("matcher-name"):
			markPoints.append(scanResult["matcher-name"])

		if scanResult.get("extracted-results"):
			if type(scanResult["extracted-results"]) == list:
				for value in scanResult["extracted-results"]:
					markPoints.append(value)

			elif type(scanResult["extracted-results"]) == str:
				markPoints.append(scanResult["extracted-results"])

		if scanResult.get("vuln-meta"):
			if type(scanResult["vuln-meta"]) == dict:
				for _, value in scanResult["vuln-meta"].items():
					if value:
						markPoints.append(value)

			elif type(scanResult["vuln-meta"]) == list:
				for value in scanResult["vuln-meta"]:
					markPoints.append(value)
			
			elif type(scanResult["vuln-meta"]) == str:
				markPoints.append(scanResult["vuln-meta"])

		return markPoints
	

	@staticmethod
	def createPoc(pocPath:str, scanResult:dict, markPoints:list=[]):
		"""Use this function to generate shell based PoC.

		Args:
		  scanResult : String Scan Output.
		  markPoints(optional) : List Keywords to mark in PoC(Keywords are case sensitive). (Default value = [])
		  port(optional) : String Port number of finding to add in PoC. (Default value = "")

		Returns:
			Example: _poc.createPoc(scanOutput, markPoints=["Vulnerable"], port="443")
		"""

		pocPath = f"{pocPath}.png"

		if not markPoints:
			markPoints = poc.getMarkpoints(scanResult)
		
		if scanResult["type"] in ["http", "javascript"]:
			image = poc.requestResponsePoc(scanResult, markPoints)
		else:
			scanResult = poc.formatTerminalPoc(scanResult)
			image = poc.generatePoc(poc.wordWrapCode(scanResult), markPoints)

		image.save(pocPath, "png")

		return pocPath
	

	@staticmethod
	def concatImage(requestImg, responseImg):
		"""
		Concats Request PoC and Response PoC to generate REQUEST_RESPONSE PoC.

		Args:
		  requestImg: request PoC image object.
		  responseImg: response PoC image object.

		Returns: 
		  object: PoC Image
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


	@staticmethod
	def parseResponseText(responseText, markpoints):
		"""
		Args:
		  responseText:
		  markpoint

		Returns: PoC String
		"""
		if responseText:
			responseList = responseText.split("\n")
			# responseText = ">\n<".join(responseText.split("><"))
			
			maxLines = len(responseList) if len(responseList) <= 25 else 25
			lineNumber1 = list(range(-25, maxLines))
			lineNumber = list(range(0, maxLines))

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


	@staticmethod
	def requestResponsePoc(scanResult:dict, markPoints:list=[]) -> object:
		"""
		Use this function to generate burpsuite like Request & Response based PoC.

		Args:
		  scanResult: nuclei scan result object.
		  markPoints(optional): List Keywords to mark in PoC(Keywords are case sensitive). (Default value = [])

		Returns:
		  object: PoC image

		Example: _poc.requestResponsePoc(responseObject, markPoints=["TRACE","DEBUG"])
		"""
		header = str()
		requestBody = scanResult.get("request")

		port = scanResult.get("port")
		host = scanResult.get("host").split(f":{port}")[0]
		if port:
			header = f"Host: {host}\nPort: {port}\n"
		else:
			header = f"Host: {host}\n"

		pocType = "REQUEST_RESPONSE"
		if scanResult["type"] != "http":
			pocType = "CODE_EXECUTION"
			requestBody = f"{header}\n{requestBody}"

		requestImg = poc.generatePoc(
			poc.wordWrapCode(requestBody), 
			markPoints=markPoints, 
			colorType="white", 
			pocType=pocType
		)

		responseImg = poc.generatePoc(
			poc.parseResponseText(poc.wordWrapCode(scanResult.get("response")), markPoints), 
			markPoints=markPoints, 
			colorType="white", 
			pocType=pocType
		)

		mergedImg = poc.concatImage(requestImg, responseImg)
		ImageOps.expand(mergedImg, border=1, fill="black")

		return mergedImg
