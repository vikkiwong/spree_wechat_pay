# encoding: utf-8
require 'rest_client'
require 'active_support/core_ext/hash/conversions'

module Spree
  class WechatpayController < StoreController
    #ssl_allowed
    skip_before_filter :verify_authenticity_token

    #OPENID = "oUG4Dwp-V28tHuyMGjG1OBinUdOI"
    OPENID = 'oQ9HCuCrGzNF4kwyZ1f91HIUOkPk'

    GATEWAY_URL = 'https://api.mch.weixin.qq.com/pay'

    def pay_options(order)
      payment_method = Spree::PaymentMethod.find(params[:payment_method_id])
      host = payment_method.preferences[:returnHost].blank? ? request.url.sub(request.fullpath, '') : payment_method.preferences[:returnHost]

      package_options = {
          bank_type: "WX",
          body: "#{order.line_items[0].product.name.slice(0,30)}等#{order.line_items.count}件",
          partner: payment_method.preferences[:partnerId],
          out_trade_no: order.number,
          total_fee: (order.total*100).to_i,
          fee_type: 1,
          notify_url: host + '/wechatpay/notify?id=' + order.id.to_s + '&payment_method_id=' + params[:payment_method_id].to_s,
          spbill_create_ip: request.remote_ip,
          # time_start: order.created_at && order.created_at.strftime("%Y%m%d%H%M%S"),
          # time_expire: order.created_at && order.created_at.in(7200).strftime("%Y%m%d%H%M%S"),
          input_charset: "UTF-8",
          openid: OPENID
      }.reject{ |k, v| v.blank? }.sort.map{ |o| { o.first => o.last } }.inject({}, &:merge)
      package_options.merge!(sign: Digest::MD5.hexdigest(package_options.sort.map{ |k, v| "#{k.to_s}=#{v.to_s}" }.push("key=#{payment_method.preferences[:partnerKey]}").join('&')).upcase)
      options = {
          appId: payment_method.preferences[:appId],
          timeStamp: Time.now.to_i.to_s,
          nonceStr: (('A'..'Z').to_a + ('a'..'z').to_a + ('0'..'9').to_a).sample(32).join,
          package: package_options.map{ |k, v| "#{ERB::Util.u(k.to_s)}=#{ERB::Util.u(v.to_s)}" }.join('&')
      }
      options.merge!(signType: 'SHA1', paySign: Digest::SHA1.hexdigest(options.merge(appKey: payment_method.preferences[:appKey]).sort.map{ |k, v| "#{k.to_s.downcase}=#{v.to_s}" }.join('&')))

      options[:orderNumber] = order.number

      options
    end

    # 生成预支付ID，并返回支付options
    def invoke_unifiedorder(order)
      payment_method = Spree::PaymentMethod.find(params[:payment_method_id])
      host = payment_method.preferences[:returnHost].blank? ? request.url.sub(request.fullpath, '') : payment_method.preferences[:returnHost]

      unifiedorder = {
          bank_type: "WX",
          body: "#{order.line_items[0].product.name.slice(0,30)}等#{order.line_items.count}件",
          trade_type: "JSAPI",
          out_trade_no: order.number,
          spbill_create_ip: request.remote_ip || '127.0.0.1',
          total_fee: (order.total*100).to_i,
          fee_type: 1,
          notify_url: host + '/wechatpay/notify?id=' + order.id.to_s, # + '%26payment_method_id=' + params[:payment_method_id].to_s,
          input_charset: "UTF-8",
          openid: OPENID,   
          appid: payment_method.preferences[:appId],
          mch_id: payment_method.preferences[:partnerId],
          nonce_str: SecureRandom.hex
        }.reject{ |k, v| v.blank? }

      Rails.logger.debug('------'*20)

      sign = generate_sign(unifiedorder, payment_method.preferences[:partnerKey])

      res = invoke_remote("#{GATEWAY_URL}/unifiedorder", make_payload(unifiedorder, sign))

      if res && res['return_code'] == 'SUCCESS'

        prepay_id = res['prepay_id']
        Rails.logger.debug("set prepay_id: #{prepay_id}")
        options = {
            appId: payment_method.preferences[:appId],
            timeStamp: Time.now.to_i.to_s,
            nonceStr: SecureRandom.hex,
            package: "prepay_id=#{prepay_id}",
            signType: "MD5"
        }

        options.merge(paySign: generate_sign(options, payment_method.preferences[:partnerKey]))

        options[:orderNumber] = order.number

        options
      else
        Rails.logger.debug '---res---'
        Rails.logger.debug("set prepay_id fail: #{res}")

        {}
      end
    end


    def checkout
      order = current_order || raise(ActiveRecord::RecordNotFound)

      render json: invoke_unifiedorder(order)
    end

    def checkout_api
      order = Spree::Order.find(params[:id]) || raise(ActiveRecord::RecordNotFound)
      render json: pay_options(order)
    end

    def notify
      order = Spree::Order.find(params[:id]) || raise(ActiveRecord::RecordNotFound)
      payment_notify_data = params.slice(:sign_type, :service_version, :input_charset, :sign, :sign_key_index, :trade_mode, :trade_state, :pay_info, :partner, :bank_type, :bank_billno, :total_fee, :fee_type, :notify_id, :transaction_id, :out_trade_no, :attach, :time_end, :transport_fee, :product_fee, :discount, :buyer_alias, :xml)

      unless payment_notify_data[:trade_state].to_s == '0' && payment_notify_data[:total_fee].to_s == ((order.total*100).to_i).to_s && payment_notify_data.try(:[], :xml).try(:[], :OpenId).present? && Digest::MD5.hexdigest(payment_notify_data.except(:xml, :sign).reject{ |k,v| v.blank? }.sort.map{ |k, v| "#{k.to_s}=#{v.to_s}" }.push("key=#{payment_method.preferences[:partnerKey]}").join('&')).upcase == payment_notify_data[:sign].to_s
        render text: "failure", layout: false
        return
      end

      if order.complete?
        render text: "success", layout: false
        return
      end

      order.payments.create!({
        :source => Spree::WechatPayNotify.create({
          :transaction_id => params[:transaction_id],
          :out_trade_no => params[:out_trade_no],
          :open_id => params[:xml][:OpenId],
          :trade_mode => params[:trade_mode],
          :trade_state => params[:trade_state],
          :total_fee => params[:total_fee],
          :source_data => payment_notify_data.to_json
        }),
        :amount => order.total,
        :payment_method => payment_method
      })
      order.next
      if order.complete?
        render text: "success", layout: false
      else
        render text: "failure", layout: false
      end
    end

    def query
      id = params[:id].split('&').first if params[:id].present?
      order = Spree::Order.find(id) || raise(ActiveRecord::RecordNotFound)
      payment_method = Spree::PaymentMethod.find(params[:payment_method_id])

      if order.complete?
        render json: { 'errCode' => 0, 'msg' => 'success'} and return
      end

      package_options = {
          out_trade_no: order.number,
          partner: payment_method.preferences[:partnerId],
      }
      package_options.merge!(sign: Digest::MD5.hexdigest(package_options.sort.map{ |k, v| "#{k.to_s}=#{v.to_s}" }.push("key=#{payment_method.preferences[:partnerKey]}").join('&')).upcase)
      options = {
          appid: payment_method.preferences[:appId],
          timestamp: Time.now.to_i.to_s,
          package: package_options.map{ |k, v| "#{ERB::Util.u(k.to_s)}=#{ERB::Util.u(v.to_s)}" }.join('&'),
      }
      options.merge!(sign_method: 'sha1', app_signature: Digest::SHA1.hexdigest(options.merge(appkey: payment_method.preferences[:appKey]).sort.map{ |k, v| "#{k.to_s}=#{v.to_s}" }.join('&')))

      access_token = self.wechat_assess_token

      pay_response = JSON.parse(Timeout::timeout(30){ Mechanize.new.post("https://api.weixin.qq.com/pay/orderquery?access_token=#{access_token}", JSON.dump(options)).body })

      if pay_response['errcode'] == 0 && pay_response['ret_code'] == 0 && pay_response['order_info.trade_state'] == 0
        order.payments.create!({
          :source => Spree::WechatPayNotify.create({
              :transaction_id => pay_response['transaction_id'],
              :out_trade_no => pay_response['out_trade_no'],
              :trade_mode => pay_response['trade_mode'],
              :trade_state => pay_response['trade_state'],
              :total_fee => pay_response['total_fee'],
              :source_data => pay_response.to_json
          }),
          :amount => order.total,
          :payment_method => payment_method
        })
        order.next
        render json: { 'errCode' => 0, 'msg' => 'success'}
      else
        render json: { 'errCode' => 1, 'msg' => 'failure'}
      end
    end

    def wechat_assess_token
      token_response = JSON.parse(Timeout::timeout(30){ Mechanize.new.get("https://api.weixin.qq.com/cgi-bin/token", { grant_type: 'client_credential', appid: payment_method.preferences[:appId], secret: payment_method.preferences[:secret] }).body })
      raise '获取微信access_token失败' if token_response["errcode"].present? || token_response["access_token"].blank?
      token_response["access_token"]
    end

    def payment_method
      Spree::PaymentMethod.find(params[:payment_method_id])
    end

    private

    def make_payload(params, sign)
      "<xml>#{params.map { |k, v| "<#{k}>#{v}</#{k}>" }.join}<sign>#{sign}</sign></xml>"
    end

    def generate_sign(params, appKey)
      query = params.sort.map do |key, value|
      "#{key}=#{value}"
      end.join('&')

      Rails.logger.debug '--query&key--'
      Rails.logger.debug "#{query}&key=#{appKey}"

      Rails.logger.debug '--sign--'
      Rails.logger.debug Digest::MD5.hexdigest("#{query}&key=#{appKey}").upcase

      Digest::MD5.hexdigest("#{query}&key=#{appKey}").upcase    
    end

    def invoke_remote(url, payload)
      r = RestClient::Request.execute(
        {
          method: :post,
          url: url,
          payload: payload,
          headers: { content_type: 'application/xml' }
        }.merge({timeout: 2, open_timeout: 3})
      )

      h = Hash.from_xml(r)

      Rails.logger.debug '---h[xml]---'
      Rails.logger.debug h['xml']

      h['xml']
    end
  end
end