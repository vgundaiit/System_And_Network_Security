#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

#include "myheader.h"


unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
   sum += (sum >> 16);                  // add carry
   return (unsigned short)(~sum);
}


void send_raw_ip_packet(struct ipheader* ip){
  struct sockaddr_in dest_info;
  int enable = 1;

  int sock = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);

  setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&enable,sizeof(enable));

  dest_info.sin_family  = AF_INET;
  dest_info.sin_addr = ip->iph_destip;

  sendto(sock,ip,ntohs(ip->iph_len),0,(struct sockaddr *)&dest_info,sizeof(dest_info));

}

/******************************************************************
  Spoof an ICMP echo response using an arbitrary source IP Address
*******************************************************************/

void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet)
{

  //Old packet properties

    int ethernet_header_length_old = 14;
    int ip_header_length_old;

    const u_char *ip_header_old;
    ip_header_old = packet + ethernet_header_length_old;
    ip_header_length_old =  ((*ip_header_old) & 0x0F);    

    ip_header_length_old = ip_header_length_old * 4;
    struct icmpheader *icmpold = (struct icmpheader*)(packet+sizeof(struct ethheader)+ip_header_length_old);

    struct ipheader * ipold = (struct ipheader *)(packet + sizeof(struct ethheader)); 

    int seq_old = icmpold->icmp_seq;
    int id_old = icmpold->icmp_id;

    char buffer[1500];

   memset(buffer, 0, 1500);

   printf("Simple spoofing to google\n");

   /*********************************************************
      Step 1: Fill in the ICMP header.
    ********************************************************/
   struct icmpheader *icmp = (struct icmpheader *)
                             (buffer + sizeof(struct ipheader));
   icmp->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.

   // Calculate the checksum for integrity
   icmp->icmp_chksum = 0;
   icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                 sizeof(struct icmpheader));
   icmp->icmp_seq = seq_old;
   icmp->icmp_id = id_old;


   /*********************************************************
      Step 2: Fill in the IP header.
    ********************************************************/
   struct ipheader *ip = (struct ipheader *) buffer;
   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_ttl = 20;
   
   
   ip->iph_sourceip.s_addr = inet_addr(inet_ntoa(ipold->iph_destip));
   ip->iph_destip.s_addr = inet_addr(inet_ntoa(ipold->iph_sourceip));

   //Working with these two below
   //ip->iph_sourceip.s_addr = inet_addr("8.8.8.1");
   //ip->iph_destip.s_addr = inet_addr("10.0.2.15");
   ip->iph_protocol = IPPROTO_ICMP;
   ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
    //ip->iph_len = 20000;


   /*********************************************************
      Step 3: Finally, send the spoofed packet
    ********************************************************/
   send_raw_ip_packet (ip);


   //  //Now ping some random ip address
   //  char buffer[1500];

   // memset(buffer, 0, 1500);

   // /*********************************************************
   //    Step 1: Fill in the ICMP header.
   //  ********************************************************/
   // struct icmpheader *icmp = (struct icmpheader *)
   //                           (buffer + sizeof(struct ipheader));
   // icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

   // // Calculate the checksum for integrity
   // icmp->icmp_chksum = 0;
   // icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
   //                               sizeof(struct icmpheader));

   // /*********************************************************
   //    Step 2: Fill in the IP header.
   //  ********************************************************/
   // struct ipheader *ip = (struct ipheader *) buffer;
   // ip->iph_ver = 4;
   // ip->iph_ihl = 5;
   // ip->iph_ttl = 20;
   // ip->iph_sourceip.s_addr = inet_addr("2.2.2.2");
   // ip->iph_destip.s_addr = inet_addr("10.0.2.15");
   // ip->iph_protocol = IPPROTO_ICMP;
   // ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
   //  //ip->iph_len = 20000;


   // /*********************************************************
   //    Step 3: Finally, send the spoofed packet
   //  ********************************************************/
   // send_raw_ip_packet (ip);



  
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;

  char filter_exp[] = "icmp[icmptype] == icmp-echo"; 
  
  bpf_u_int32 net;


  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);              

  pcap_setfilter(handle, &fp);                                

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                    

  pcap_close(handle);   //Close the handle
  return 0;
}