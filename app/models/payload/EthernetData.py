class EthernetData:

  destination_ip: str = None
  source_ip: str = None
  protocol: str = None
  data: str = None

  def __init__(
    self,
    data: str,
  ):
    data_segments = data.split("-") 
    if len(data_segments) == 4:

      self.destination_ip = data_segments[0]
      self.source_ip = data_segments[1]
      self.protocol = data_segments[2]
      self.data = data_segments[3]
    
    else:
      self.data = data
  
  def dumps(self) -> str:
    return f"{self.destination_ip}-{self.source_ip}-{self.protocol}-{self.data}"