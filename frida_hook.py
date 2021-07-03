import frida
import sys
import time

class FridaHoocker():
	def __init__(self):
		self.script = None
		self._process_terminated = False

	def on_destroyed(self):
		print("[*] Destroyed!")
		sys.exit(1)
	
	def on_detach(self):
		self._process_terminated = True
		print("[*] Detach")
	
	def on_message(self, message, data):
		if message['type'] == 'send':
				msg_data = message['payload']
	
				if msg_data['name'] == 'log':
					try:
						print('%s' % msg_data['payload'])
						self.script.post({'type': 'ack'})
					except Exception as e:
						print(e)
		else:
			print('[*] Error: %s' % message)
	
	def main(self, target_process):
		session = frida.attach(target_process)
	
		with open("script.js") as fp:
			script_js = fp.read()
	
		fp.close()
	
		self.script = session.create_script(script_js)
		self.script.on('destroyed', self.on_destroyed)
		self.script.on('message', self.on_message)
		session.on('detached', self.on_detach)

		self.script.load()
		
	
		frida.resume(target_process)
	
		print("[*] Ctrl+C to detach from program.\n")
		while True:
			try:
				time.sleep(0.5)
			except KeyboardInterrupt:
				break
	
		frida.kill(target_process)
		session.detach()

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print("Usage: %s <process name or PID>" % __file__)
		sys.exit(1)
	
	try:
		target_process = int(sys.argv[1])
	except ValueError:
		target_process = frida.spawn(sys.argv[1])
	
	frida_hook = FridaHoocker()
	frida_hook.main(target_process)