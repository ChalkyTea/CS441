class EthernetData:

  dest_ip: str = None
  src_ip: str = None
  protocol: str = None
  data: str = None

  def __init__(
    self,
    data: str,
  ):
    data_segments = data.split("-") 
    if len(data_segments) == 4:
      self.dest_ip = data_segments[0]
      self.src_ip = data_segments[1]
      self.protocol = data_segments[2]
      self.data = data_segments[3]
    
    else:
      self.data = data
  
  def dumps(self) -> str:
    return f"{self.dest_ip}-{self.src_ip}-{self.protocol}-{self.data}"